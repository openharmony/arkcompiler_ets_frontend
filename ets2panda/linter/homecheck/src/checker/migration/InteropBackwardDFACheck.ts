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

import {
    Type,
    ArkMethod,
    ArkAssignStmt,
    FieldSignature,
    Stmt,
    Scene,
    Value,
    CallGraph,
    ArkParameterRef,
    ArkInstanceFieldRef,
    ArkInstanceInvokeExpr,
    FunctionType,
    AnyType,
    ClassType,
    ArkStaticInvokeExpr,
    AbstractInvokeExpr,
    UnknownType,
    Local,
    ArkNamespace,
} from 'arkanalyzer/lib';
import Logger, { LOG_MODULE_TYPE } from 'arkanalyzer/lib/utils/logger';
import { BaseChecker, BaseMetaData } from '../BaseChecker';
import { Rule, Defects, MatcherCallback } from '../../Index';
import { IssueReport } from '../../model/Defects';
import { DVFGNode } from 'arkanalyzer/lib/VFG/DVFG';
import { CALL_DEPTH_LIMIT, GlobalCallGraphHelper, DVFGHelper } from './Utils';
import { findInteropRule } from './InteropRuleInfo';
import { Language } from 'arkanalyzer/lib/core/model/ArkFile';

const logger = Logger.getLogger(LOG_MODULE_TYPE.HOMECHECK, 'InteropBackwardDFACheck');
const gMetaData: BaseMetaData = {
    severity: 1,
    ruleDocPath: '',
    description: '',
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

    public registerMatchers(): MatcherCallback[] {
        const matchBuildCb: MatcherCallback = {
            matcher: undefined,
            callback: this.check,
        };
        return [matchBuildCb];
    }

    public check = (scene: Scene): void => {
        this.cg = GlobalCallGraphHelper.getCGInstance(scene);

        for (let arkFile of scene.getFiles()) {
            for (let clazz of arkFile.getClasses()) {
                for (let mtd of clazz.getMethods()) {
                    this.processArkMethod(mtd, scene);
                }
            }
            for (let namespace of arkFile.getAllNamespacesUnderThisFile()) {
                this.processNameSpace(namespace, scene);
            }
        }
    };

    public processNameSpace(namespace: ArkNamespace, scene: Scene): void {
        for (let clazz of namespace.getClasses()) {
            for (let mtd of clazz.getMethods()) {
                this.processArkMethod(mtd, scene);
            }
        }
    }

    private processArkMethod(target: ArkMethod, scene: Scene): void {
        const currentLang = target.getLanguage();
        if (currentLang === Language.UNKNOWN) {
            logger.warn(`cannot find the language for method: ${target.getSignature()}`);
            return;
        }
        const stmts = target.getBody()?.getCfg().getStmts() ?? [];
        for (const stmt of stmts) {
            const invoke = stmt.getInvokeExpr();
            let isReflect = false;
            let paramIdx = -1;
            if (invoke && invoke instanceof ArkInstanceInvokeExpr) {
                if (invoke.getBase().getName() === 'Reflect') {
                    isReflect = true;
                    paramIdx =
                        REFLECT_API.get(invoke.getMethodSignature().getMethodSubSignature().getMethodName()) ?? -1;
                }
            }
            if (invoke && invoke instanceof ArkStaticInvokeExpr) {
                const methodSig = invoke.getMethodSignature();
                const classSig = methodSig.getDeclaringClassSignature();
                if (classSig.getClassName() === 'ObjectConstructor' || classSig.getClassName() === 'Object') {
                    paramIdx =
                        OBJECT_API.get(invoke.getMethodSignature().getMethodSubSignature().getMethodName()) ?? -1;
                }
            }
            if (paramIdx === -1) {
                continue;
            }
            DVFGHelper.buildSingleDVFG(target, scene);

            const objDefs: Stmt[] = [];
            const getKey = (v: Value): Value | FieldSignature => {
                return v instanceof ArkInstanceFieldRef ? v.getFieldSignature() : v;
            };
            const param: Value | FieldSignature = getKey((invoke as AbstractInvokeExpr).getArg(paramIdx));
            Array.from(DVFGHelper.getOrNewDVFGNode(stmt, scene).getIncomingEdge())
                .map(e => (e.getSrcNode() as DVFGNode).getStmt())
                .filter(s => {
                    return s instanceof ArkAssignStmt && param === getKey(s.getLeftOp());
                })
                .forEach(def => {
                    objDefs.push(def);
                });
            this.processObjDefs(objDefs, scene, currentLang, isReflect, stmt, target)
        }
    }

    private processObjDefs(objDefs: Stmt[], scene: Scene, currentLang: Language, isReflect: boolean, stmt: Stmt, target: ArkMethod): void {
        for (const objDef of objDefs) {
            let result: ObjDefInfo[] = [];
            let checkAll = { value: true };
            let visited: Set<Stmt> = new Set();
            this.checkFromStmt(objDef, scene, result, checkAll, visited);
            result.forEach(objDefInfo => {
                const objDefLang = objDefInfo.objDef.getCfg()?.getDeclaringMethod().getLanguage() ?? Language.UNKNOWN;
                const typeDefLang = this.getTypeDefinedLang(objDefInfo.objType, scene) ?? objDefLang;
                if (objDefLang === Language.UNKNOWN || typeDefLang === Language.UNKNOWN) {
                    logger.warn(`cannot find the language for def: ${objDefInfo.objDef.toString()}`);
                    return;
                }
                const interopRule = findInteropRule(currentLang, objDefLang, typeDefLang, isReflect);
                if (!interopRule) {
                    return;
                }
                const line = stmt.getOriginPositionInfo().getLineNo();
                const column = stmt.getOriginPositionInfo().getColNo();
                const problem = 'Interop';
                const desc = `${interopRule.description}: ${this.generateDesc(objDefInfo.objDef)} (${interopRule.ruleId
                    })`;
                const severity = interopRule.severity;
                const ruleId = this.rule.ruleId;
                const filePath = target.getDeclaringArkFile()?.getFilePath() ?? '';
                const defeats = new Defects(
                    line,
                    column,
                    column,
                    problem,
                    desc,
                    severity,
                    ruleId,
                    filePath,
                    '',
                    true,
                    false,
                    false
                );
                this.issues.push(new IssueReport(defeats, undefined));
            });
            if (!checkAll) {
                // report issue
            }
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

    private checkFromStmt(
        stmt: Stmt,
        scene: Scene,
        res: ObjDefInfo[],
        checkAll: { value: boolean },
        visited: Set<Stmt>,
        depth: number = 0
    ): void {
        if (depth > CALL_DEPTH_LIMIT) {
            checkAll.value = false;
            return;
        }
        const node = DVFGHelper.getOrNewDVFGNode(stmt, scene);
        let worklist: DVFGNode[] = [node];
        while (worklist.length > 0) {
            const current = worklist.shift()!;
            const currentStmt = current.getStmt();
            if (visited.has(currentStmt)) {
                continue;
            }
            visited.add(currentStmt);
            if (currentStmt instanceof ArkAssignStmt) {
                const rightOp = currentStmt.getRightOp();
                if (rightOp instanceof ArkInstanceFieldRef) {
                    const base = rightOp.getBase();
                    if (base instanceof Local && base.getDeclaringStmt()) {
                        worklist.push(DVFGHelper.getOrNewDVFGNode(base.getDeclaringStmt()!, scene));
                        continue;
                    }
                }
                const rightOpTy = rightOp.getType();
                const isObjectTy = (ty: Type): boolean => {
                    return ty instanceof ClassType && ty.getClassSignature().getClassName() === 'Object';
                };
                const isESObjectTy = (ty: Type): boolean => {
                    return ty.toString() === 'ESObject';
                };
                const isAnyTy = (ty: Type): ty is AnyType => {
                    return ty instanceof AnyType;
                };
                const isUnkwonTy = (ty: Type): ty is UnknownType => {
                    return ty instanceof UnknownType;
                };
                if (
                    !isObjectTy(rightOpTy) &&
                    !isESObjectTy(rightOpTy) &&
                    !isAnyTy(rightOpTy) &&
                    !isUnkwonTy(rightOpTy)
                ) {
                    res.push({ objDef: currentStmt, objType: rightOpTy });
                    continue;
                }
            }
            const callsite = this.cg.getCallSiteByStmt(currentStmt);
            callsite.forEach(cs => {
                const declaringMtd = this.cg.getArkMethodByFuncID(cs.calleeFuncID);
                if (!declaringMtd || !declaringMtd.getCfg()) {
                    return;
                }
                DVFGHelper.buildSingleDVFG(declaringMtd, scene);
                declaringMtd
                    .getReturnStmt()
                    .forEach(r => this.checkFromStmt(r, scene, res, checkAll, visited, depth + 1));
            });
            const paramRef = this.isFromParameter(currentStmt);
            if (paramRef) {
                const paramIdx = paramRef.getIndex();
                const callsites = this.cg.getInvokeStmtByMethod(
                    currentStmt.getCfg().getDeclaringMethod().getSignature()
                );
                callsites.forEach(cs => {
                    const declaringMtd = cs.getCfg().getDeclaringMethod();
                    DVFGHelper.buildSingleDVFG(declaringMtd, scene);
                });
                this.collectArgDefs(paramIdx, callsites, scene).forEach(d =>
                    this.checkFromStmt(d, scene, res, checkAll, visited, depth + 1)
                );
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

    private collectArgDefs(argIdx: number, callsites: Stmt[], scene: Scene): Stmt[] {
        const getKey = (v: Value): Value | FieldSignature => {
            return v instanceof ArkInstanceFieldRef ? v.getFieldSignature() : v;
        };
        return callsites.flatMap(callsite => {
            const target: Value | FieldSignature = getKey(callsite.getInvokeExpr()!.getArg(argIdx));
            return Array.from(DVFGHelper.getOrNewDVFGNode(callsite, scene).getIncomingEdge())
                .map(e => (e.getSrcNode() as DVFGNode).getStmt())
                .filter(s => {
                    return s instanceof ArkAssignStmt && target === getKey(s.getLeftOp());
                });
        });
    }

    private getTypeDefinedLang(type: Type, scene: Scene): Language | undefined {
        let file = undefined;
        if (type instanceof ClassType) {
            file = scene.getFile(type.getClassSignature().getDeclaringFileSignature());
        } else if (type instanceof FunctionType) {
            file = scene.getFile(type.getMethodSignature().getDeclaringClassSignature().getDeclaringFileSignature());
        }
        if (file) {
            return file.getLanguage();
        } else {
            logger.error(`fail to identify which file the type definition ${type.toString()} is in.`);
        }
        return undefined;
    }
}
