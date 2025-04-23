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

import { Type, ArkMethod, ArkAssignStmt, FieldSignature, Stmt, Scene, Value, CallGraph, ArkParameterRef, ArkInstanceFieldRef, FunctionType, ClassType } from "arkanalyzer/lib";
import Logger, { LOG_MODULE_TYPE } from 'arkanalyzer/lib/utils/logger';
import { BaseChecker, BaseMetaData } from "../BaseChecker";
import { Rule, Defects, MatcherCallback } from "../../Index";
import { IssueReport } from "../../model/Defects";
import { DVFGNode } from "arkanalyzer/lib/VFG/DVFG";
import { CALL_DEPTH_LIMIT, DVFGHelper, GlobalCallGraphHelper } from './Utils';
import { Language } from 'arkanalyzer/lib/core/model/ArkFile';


const logger = Logger.getLogger(LOG_MODULE_TYPE.HOMECHECK, 'InteropAssignCheck');
const gMetaData: BaseMetaData = {
    severity: 1,
    ruleDocPath: '',
    description: 'should not pass or assign object created in 1.2 to value of static Object type'
};

const RULE_ID = 'interop-pass-or-assign-to-static-Object-type';

class ObjDefInfo {
    objDef: Stmt;
    objType: Type;
}

export class InteropAssignCheck implements BaseChecker {
    readonly metaData: BaseMetaData = gMetaData;
    public rule: Rule;
    public defects: Defects[] = [];
    public issues: IssueReport[] = [];
    private cg: CallGraph;


    public registerMatchers(): MatcherCallback[] {
        const matchBuildCb: MatcherCallback = {
            matcher: undefined,
            callback: this.check
        }
        return [matchBuildCb];
    }

    public check = (scene: Scene) => {
        this.cg = GlobalCallGraphHelper.getCGInstance(scene);

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

    public processArkMethod(target: ArkMethod, scene: Scene) {
        const assigns: Stmt[] = [];
        if (target.getLanguage() === Language.ARKTS1_2) {
            assigns.push(...this.checkObjectParams(target));
        } else if (target.getLanguage() === Language.ARKTS1_1) {
            assigns.push(...this.checkAssignToObjectField(target, scene));
        } else {
            // Is this ok?
            return;
        }
        assigns.forEach(assign => {
            let result: ObjDefInfo[] = [];
            let checkAll = { value: true };
            let visited: Set<Stmt> = new Set();
            this.checkFromStmt(assign, scene, result, checkAll, visited);
            result.forEach(objDefInfo => {
                const typeDefLang = this.getTypeDefinedLang(objDefInfo, scene);
                if (typeDefLang === Language.ARKTS1_2) {
                    return;
                }
                let line;
                let column;
                if (assign instanceof ArkAssignStmt && assign.getRightOp() instanceof ArkParameterRef) {
                    line = objDefInfo.objDef.getOriginPositionInfo().getLineNo();
                    column = objDefInfo.objDef.getOriginPositionInfo().getColNo();
                } else {
                    line = assign.getOriginPositionInfo().getLineNo();
                    column = assign.getOriginPositionInfo().getColNo();
                }
                const problem = 'Interop';
                const desc = `${this.metaData.description}: ${this.generateDesc(objDefInfo.objDef)} (${RULE_ID})`;
                const severity = this.metaData.severity;
                const ruleId = this.rule.ruleId;
                const filePath = target.getDeclaringArkFile()?.getFilePath() ?? '';
                const defeats = new Defects(line, column, column, problem, desc, severity, ruleId, filePath, '', true, false, false);
                this.issues.push(new IssueReport(defeats, undefined));
            });
            if (!checkAll) {
                // report issue
            }
        });
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

    private checkObjectParams(method: ArkMethod): Stmt[] {
        const res: Stmt[] = [];
        const stmts = method.getBody()?.getCfg().getStmts() ?? [];
        for (const stmt of stmts) {
            if (stmt instanceof ArkAssignStmt && stmt.getRightOp() instanceof ArkParameterRef) {
                if (this.isObjectTy((stmt.getRightOp() as ArkParameterRef).getType())) {
                    res.push(stmt);
                }
            } else {
                break;
            }
        }
        return res;
    }

    private checkAssignToObjectField(method: ArkMethod, scene: Scene) {
        const res: Stmt[] = [];
        const stmts = method.getBody()?.getCfg().getStmts() ?? [];
        for (const stmt of stmts) {
            if (!(stmt instanceof ArkAssignStmt)) {
                continue;
            }
            const leftOp = stmt.getLeftOp();
            if (!(leftOp instanceof ArkInstanceFieldRef)) {
                continue;
            }
            if (!this.isObjectTy(leftOp.getType())) {
                continue;
            }
            const baseTy = leftOp.getBase().getType();
            if (baseTy instanceof ClassType) {
                const klass = scene.getClass(baseTy.getClassSignature());
                if (!klass) {
                    logger.warn(`check field of type 'Object' failed: cannot find arkclass by sig ${baseTy.getClassSignature().toString()}`);
                } else if (klass.getLanguage() === Language.ARKTS1_2) {
                    res.push(stmt);
                }
            } else {
                logger.warn(`check field of type 'Object' failed: unexpected base type ${baseTy.toString()}`);
            }
        }
        return res;
    }

    private checkFromStmt(stmt: Stmt, scene: Scene, res: ObjDefInfo[], checkAll: { value: boolean }, visited: Set<Stmt>, depth: number = 0) {
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
            if (stmt instanceof ArkAssignStmt) {
                const rightOpTy = stmt.getRightOp().getType();
                if (!this.isObjectTy(rightOpTy)) {
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
                DVFGHelper.buildSingleDVFG(declaringMtd, scene);
                declaringMtd.getReturnStmt().forEach(r => this.checkFromStmt(r, scene, res, checkAll, visited, depth + 1));
            })
            const paramRef = this.isFromParameter(currentStmt);
            if (paramRef) {
                const paramIdx = paramRef.getIndex();
                const callsites = this.cg.getInvokeStmtByMethod(currentStmt.getCfg().getDeclaringMethod().getSignature());
                callsites.forEach(cs => {
                    const declaringMtd = cs.getCfg().getDeclaringMethod();
                    DVFGHelper.buildSingleDVFG(declaringMtd, scene);
                });
                this.collectArgDefs(paramIdx, callsites, scene).forEach(d => this.checkFromStmt(d, scene, res, checkAll, visited, depth + 1));
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
        const getKey = (v: Value) => {
            return v instanceof ArkInstanceFieldRef ? v.getFieldSignature() : v
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

    private isObjectTy(ty: Type) {
        return ty instanceof ClassType && ty.getClassSignature().getClassName() === 'Object';
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