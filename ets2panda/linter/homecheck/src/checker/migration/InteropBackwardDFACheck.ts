/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { Type, ArkMethod, ArkAssignStmt, FieldSignature, Stmt, Scene, Value, DVFGBuilder, ArkFile, ArkNewExpr, CallGraph, CallGraphBuilder, ArkParameterRef, ArkInstanceFieldRef, ArkField, ArkInstanceInvokeExpr, ClassSignature, FunctionType, AnyType, MethodSignature, ClassType, ArkStaticInvokeExpr, AbstractInvokeExpr } from "arkanalyzer/lib";
import Logger, { LOG_MODULE_TYPE } from 'arkanalyzer/lib/utils/logger';
import { BaseChecker, BaseMetaData } from "../BaseChecker";
import { Rule, Defects, MatcherCallback } from "../../Index";
import { IssueReport } from "../../model/Defects";
import { DVFG, DVFGNode } from "arkanalyzer/lib/VFG/DVFG";
import { CALL_DEPTH_LIMIT, GlobalCallGraphHelper } from './Utils';
import { InteropRuleInfo, findInteropRule } from './InteropRuleInfo';
import { Language } from 'arkanalyzer/lib/core/model/ArkFile';


const logger = Logger.getLogger(LOG_MODULE_TYPE.HOMECHECK, 'InteropBackwardDFACheck');
const gMetaData: BaseMetaData = {
    severity: 1,
    ruleDocPath: '',
    description: ''
};

const REFLECT_API: Map<string, number> = new Map([
    ['apply', 0],
    ['construct', 0],
    ['defineProperty', 0],
    ['deleteProperty', 0],
    ['get', 0],
    ['getOwnPropertyDescriptor', 0],
    ['getPrototypeOf', 0],
    ['has', 0],
    ['isExtensible', 0],
    ['ownKeys', 0],
    ['preventExtensions', 0],
    ['set', 0],
    ['setPrototypeOf', 0],
]);

const OBJECT_API: Map<string, number> = new Map([
    ['getOwnPropertyDescriptor', 0],
    ['getOwnPropertyDescriptors', 0],
    ['getOwnPropertyNames', 0],
    ['isExtensible', 0],
    ['isFrozen', 0],
    ['isSealed', 0],
    ['keys', 0],
    ['setPrototypeOf', 0],
    ['values', 0],
    ['assign', 1],
    ['entries', 0],
]);

class ObjDefInfo {
    objDef: Stmt;
    objType: Type;
}

export class InteropBackwardDFACheck implements BaseChecker {
    readonly metaData: BaseMetaData = gMetaData;
    public rule: Rule;
    public defects: Defects[] = [];
    public issues: IssueReport[] = [];
    private cg: CallGraph;
    private dvfg: DVFG;
    private dvfgBuilder: DVFGBuilder;
    private visited: Set<ArkMethod> = new Set();

    public registerMatchers(): MatcherCallback[] {
        const matchBuildCb: MatcherCallback = {
            matcher: undefined,
            callback: this.check
        }
        return [matchBuildCb];
    }

    public check = (scene: Scene) => {
        this.cg = GlobalCallGraphHelper.getCGInstance(scene);

        this.dvfg = new DVFG(this.cg);
        this.dvfgBuilder = new DVFGBuilder(this.dvfg, scene);

        for (let arkFile of scene.getFiles()) {
            for (let clazz of arkFile.getClasses()) {
                for (let mtd of clazz.getMethods()) {
                    this.processArkMethod(mtd, scene);
                }
            }
            for (let namespace of arkFile.getAllNamespacesUnderThisFile()) {
                for (let clazz of namespace.getClasses()) {
                    for (let mtd of clazz.getMethods()) {
                        this.processArkMethod(mtd, scene);
                    }
                }
            }
        }
    }

    private processArkMethod(target: ArkMethod, scene: Scene) {
        const currentLang = target.getLanguage();
        const stmts = target.getBody()?.getCfg().getStmts() ?? [];
        for (const stmt of stmts) {
            const invoke = stmt.getInvokeExpr();
            let isReflect = false;
            let paramIdx = -1;
            if (invoke && invoke instanceof ArkInstanceInvokeExpr) {
                if (invoke.getBase().getName() === 'Reflect') {
                    isReflect = true;
                    paramIdx = REFLECT_API.get(invoke.getMethodSignature().getMethodSubSignature().getMethodName()) ?? -1;
                }
            }
            if (invoke && invoke instanceof ArkStaticInvokeExpr) {
                const methodSig = invoke.getMethodSignature();
                const classSig = methodSig.getDeclaringClassSignature();
                if (classSig.getClassName() === 'ObjectConstructor' || classSig.getClassName() === 'Object') {
                    paramIdx = OBJECT_API.get(invoke.getMethodSignature().getMethodSubSignature().getMethodName()) ?? -1;
                }
            }
            if (paramIdx === -1) {
                continue;
            }
            this.tryBuildDVFG(target);

            const objDefs: Stmt[] = [];
            const getKey = (v: Value) => {
                return v instanceof ArkInstanceFieldRef ? v.getFieldSignature() : v
            };
            const param: Value | FieldSignature = getKey((invoke as AbstractInvokeExpr).getArg(paramIdx));
            Array.from(this.dvfg.getOrNewDVFGNode(stmt).getIncomingEdge())
                .map(e => (e.getSrcNode() as DVFGNode).getStmt())
                .filter(s => {
                    return s instanceof ArkAssignStmt && param === getKey(s.getLeftOp());
                }).forEach(def => {
                    objDefs.push(def);
                });

            for (const objDef of objDefs) {
                let result: ObjDefInfo[] = [];
                let checkAll = { value: true };
                let visited: Set<Stmt> = new Set();
                this.checkFromStmt(objDef, scene, result, checkAll, visited);
                result.forEach(objDefInfo => {
                    const typeDefLang = this.getTypeDefinedLang(objDefInfo, scene);
                    if (currentLang === typeDefLang && currentLang !== Language.UNKNOWN) {
                        return;
                    }
                    const interopRule = findInteropRule(currentLang, typeDefLang, isReflect);
                    if (!interopRule) {
                        return logger.error(`cannot find a interop rule: methodLang: ${currentLang}, typeDefLang: ${typeDefLang}`);
                    }
                    const line = stmt.getOriginPositionInfo().getLineNo();
                    const column = stmt.getOriginPositionInfo().getColNo();
                    const desc = `${interopRule.description}: ${this.generateDesc(objDefInfo.objDef)} (${interopRule.ruleId})`;
                    const severity = interopRule.severity;
                    const ruleId = this.rule.ruleId;
                    const filePath = target.getDeclaringArkFile()?.getFilePath() ?? '';
                    const defeats = new Defects(line, column, column, desc, severity, ruleId, filePath, '', true, false, false);
                    this.issues.push(new IssueReport(defeats, undefined));
                });
                if (!checkAll) {
                    // report issue
                }
            }

        }
    }

    private tryBuildDVFG(method: ArkMethod) {
        if (!this.visited.has(method)) {
            this.dvfgBuilder.buildForSingleMethod(method);
            this.visited.add(method);
        }
    }

    private generateDesc(objDef: Stmt): string {
        const obj = (objDef as ArkAssignStmt).getRightOp();
        const objFile = objDef.getCfg()?.getDeclaringMethod().getDeclaringArkFile();
        const objPos = objDef.getOperandOriginalPosition(obj);
        let objDesc = '';
        if (objFile && objPos) {
            const fileName = objFile.getName();
            const line = objPos.getFirstLine();
            const col = objPos.getFirstCol();
            objDesc = `using object defined at line ${line}, column ${col} in file '${fileName}'`;
        }
        return objDesc;
    }

    private checkFromStmt(stmt: Stmt, scene: Scene, res: ObjDefInfo[], checkAll: { value: boolean }, visited: Set<Stmt>, depth: number = 0) {
        if (depth > CALL_DEPTH_LIMIT) {
            checkAll.value = false;
            return;
        }
        const node = this.dvfg.getOrNewDVFGNode(stmt);
        let worklist: DVFGNode[] = [node];
        while (worklist.length > 0) {
            const current = worklist.shift()!;
            const currentStmt = current.getStmt();
            if (visited.has(currentStmt)) {
                continue;
            }
            visited.add(currentStmt);
            if (stmt instanceof ArkAssignStmt) {
                const rightOpTy = stmt.getRightOp().getType();
                const isObjectTy = (ty: Type) => { return ty instanceof ClassType && ty.getClassSignature().getClassName() === 'Object' }
                if (!isObjectTy(rightOpTy) && rightOpTy.toString() !== 'ESObject' && !(rightOpTy instanceof AnyType)) {
                    res.push({ objDef: stmt, objType: rightOpTy });
                    continue;
                }
            }
            const callsite = this.cg.getCallSiteByStmt(currentStmt);
            callsite.forEach(cs => {
                const declaringMtd = this.cg.getArkMethodByFuncID(cs.calleeFuncID);
                if (!declaringMtd || !declaringMtd.getCfg()) {
                    return;
                }
                if (!this.visited.has(declaringMtd)) {
                    this.dvfgBuilder.buildForSingleMethod(declaringMtd);
                    this.visited.add(declaringMtd);
                }
                declaringMtd.getReturnStmt().forEach(r => this.checkFromStmt(r, scene, res, checkAll, visited, depth + 1));
            })
            const paramRef = this.isFromParameter(currentStmt);
            if (paramRef) {
                const paramIdx = paramRef.getIndex();
                const callsites = this.cg.getInvokeStmtByMethod(currentStmt.getCfg().getDeclaringMethod().getSignature());
                callsites.forEach(cs => {
                    const declaringMtd = cs.getCfg().getDeclaringMethod();
                    if (!this.visited.has(declaringMtd)) {
                        this.dvfgBuilder.buildForSingleMethod(declaringMtd);
                        this.visited.add(declaringMtd);
                    }
                });
                this.collectArgDefs(paramIdx, callsites).forEach(d => this.checkFromStmt(d, scene, res, checkAll, visited, depth + 1));
            }
            current.getIncomingEdge().forEach(e => worklist.push(e.getSrcNode() as DVFGNode));
        }
    }

    private isFromParameter(stmt: Stmt): ArkParameterRef | undefined {
        if (!(stmt instanceof ArkAssignStmt)) {
            return undefined;
        }
        const rightOp = stmt.getRightOp();
        if (rightOp instanceof ArkParameterRef) {
            return rightOp;
        }
        return undefined;
    }

    private collectArgDefs(argIdx: number, callsites: Stmt[]): Stmt[] {
        const getKey = (v: Value) => {
            return v instanceof ArkInstanceFieldRef ? v.getFieldSignature() : v
        };
        return callsites.flatMap(callsite => {
            const target: Value | FieldSignature = getKey(callsite.getInvokeExpr()!.getArg(argIdx));
            return Array.from(this.dvfg.getOrNewDVFGNode(callsite).getIncomingEdge())
                .map(e => (e.getSrcNode() as DVFGNode).getStmt())
                .filter(s => {
                    return s instanceof ArkAssignStmt && target === getKey(s.getLeftOp());
                });
        });
    }

    private getTypeDefinedLang(objDefInfo: ObjDefInfo, scene: Scene): Language {
        const def = objDefInfo.objDef;
        const type = objDefInfo.objType;
        let file;
        if (type instanceof ClassType) {
            file = scene.getFile(type.getClassSignature().getDeclaringFileSignature());
        } else if (type instanceof FunctionType) {
            file = scene.getFile(type.getMethodSignature().getDeclaringClassSignature().getDeclaringFileSignature());
        } else {
            file = def.getCfg()?.getDeclaringMethod().getDeclaringArkFile();
        }
        if (file) {
            return file.getLanguage();
        } else {
            logger.error(`fail to identify which file the type definition ${type.toString()} is in.`);
            return Language.UNKNOWN;
        }
    }
}