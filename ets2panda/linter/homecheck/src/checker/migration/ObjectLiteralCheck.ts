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

import { ArkMethod, ArkAssignStmt, FieldSignature, Stmt, Scene, Value, DVFGBuilder, ArkInstanceOfExpr, ArkNewExpr, CallGraph, CallGraphBuilder, ArkParameterRef, ArkInstanceFieldRef } from "arkanalyzer/lib";
import Logger, { LOG_MODULE_TYPE } from 'arkanalyzer/lib/utils/logger';
import { BaseChecker, BaseMetaData } from "../BaseChecker";
import { Rule, Defects, MatcherCallback } from "../../Index";
import { IssueReport } from "../../model/Defects";
import { DVFG, DVFGNode } from "arkanalyzer/lib/VFG/DVFG";

const logger = Logger.getLogger(LOG_MODULE_TYPE.HOMECHECK, 'ObjectLiteralCheck');
const gMetaData: BaseMetaData = {
    severity: 1,
    ruleDocPath: "",
    description: 'Object literal shall generate instance of a specific class.'
};

export class ObjectLiteralCheck implements BaseChecker {
    readonly metaData: BaseMetaData = gMetaData;
    public rule: Rule;
    public defects: Defects[] = [];
    public issues: IssueReport[] = [];
    private cg: CallGraph;
    private dvfg: DVFG;

    public registerMatchers(): MatcherCallback[] {
        const matchBuildCb: MatcherCallback = {
            matcher: undefined,
            callback: this.check
        }
        return [matchBuildCb];
    }

    public check = (scene: Scene) => {
        this.cg = new CallGraph(scene);
        let cgBuilder = new CallGraphBuilder(this.cg, scene);
        cgBuilder.buildDirectCallGraphForScene();
        let entries = this.cg.getEntries().map(funcId => this.cg.getArkMethodByFuncID(funcId)!.getSignature());
        cgBuilder.buildClassHierarchyCallGraph(entries, true);

        this.dvfg = new DVFG(this.cg);
        const dvfgBuilder = new DVFGBuilder(this.dvfg, scene);
        dvfgBuilder.build();

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
        const stmts = target.getBody()?.getCfg().getStmts() ?? [];
        for (const stmt of stmts) {
            if (!(stmt instanceof ArkAssignStmt)) {
                continue;
            }
            const rightOp = stmt.getRightOp();
            if (!(rightOp instanceof ArkInstanceOfExpr)) {
                continue;
            }
            let result: Stmt[] = [];
            let checkAll = { value: true };
            this.checkFromStmt(stmt, scene, result, checkAll);
            result.forEach(s => this.addIssueReport(s, (s as ArkAssignStmt).getRightOp()));
            if (!checkAll.value) {
                this.addIssueReport(stmt, rightOp);
            }
        }

    }

    private checkFromStmt(stmt: Stmt, scene: Scene, res: Stmt[], checkAll: { value: boolean }, depth: number = 0) {
        if (depth > 2) {
            checkAll.value = false;
            return;
        }
        const node = this.dvfg.getOrNewDVFGNode(stmt);
        let worklist: DVFGNode[] = [node];
        while (worklist.length > 0) {
            const current = worklist.shift()!;
            const currentStmt = current.getStmt();
            if (this.isObjectLiteral(currentStmt, scene)) {
                res.push(currentStmt);
                continue;
            }
            const callsite = this.cg.getCallSiteByStmt(currentStmt);
            callsite.forEach(cs => {
                let returnStmts = this.cg.getArkMethodByFuncID(cs.calleeFuncID)?.getReturnStmt();
                returnStmts?.forEach(r => this.checkFromStmt(r, scene, res, checkAll, depth + 1));
            })
            const paramRef = this.isFromParameter(currentStmt);
            if (paramRef) {
                const paramIdx = paramRef.getIndex();
                const callsites = this.cg.getInvokeStmtByMethod(currentStmt.getCfg().getDeclaringMethod().getSignature());
                this.collectArgDefs(paramIdx, callsites).forEach(d => this.checkFromStmt(d, scene, res, checkAll, depth + 1));
            }
            current.getIncomingEdge().forEach(e => worklist.push(e.getSrcNode() as DVFGNode));
        }
    }

    private isObjectLiteral(stmt: Stmt, scene: Scene): boolean {
        if (!(stmt instanceof ArkAssignStmt)) {
            return false;
        }
        const rightOp = stmt.getRightOp();
        if (!(rightOp instanceof ArkNewExpr)) {
            return false;
        }
        const classSig = rightOp.getClassType().getClassSignature();
        if (scene.getClass(classSig)?.isAnonymousClass()) {
            return true;
        }
        return false;
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

    private addIssueReport(stmt: Stmt, operand: Value) {
        const severity = this.rule.alert ?? this.metaData.severity;
        const warnInfo = this.getLineAndColumn(stmt, operand);
        let defects = new Defects(warnInfo.line, warnInfo.startCol, warnInfo.endCol, this.metaData.description, severity, this.rule.ruleId,
            warnInfo.filePath, this.metaData.ruleDocPath, true, false, false);
        this.issues.push(new IssueReport(defects, undefined));
    }

    private getLineAndColumn(stmt: Stmt, operand: Value) {
        const arkFile = stmt.getCfg()?.getDeclaringMethod().getDeclaringArkFile();
        const originPosition = stmt.getOperandOriginalPosition(operand);
        if (arkFile && originPosition) {
            const originPath = arkFile.getFilePath();
            const line = originPosition.getFirstLine();
            const startCol = originPosition.getFirstCol();
            const endCol = startCol;
            return { line, startCol, endCol, filePath: originPath };
        } else {
            logger.debug('ArkFile is null.');
        }
        return { line: -1, startCol: -1, endCol: -1, filePath: '' };
    }
}