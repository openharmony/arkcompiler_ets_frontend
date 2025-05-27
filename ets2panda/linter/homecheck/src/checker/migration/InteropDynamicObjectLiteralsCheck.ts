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
    ArkMethod,
    ArkAssignStmt,
    FieldSignature,
    Stmt,
    Scene,
    Value,
    DVFGBuilder,
    ArkInstanceOfExpr,
    ArkNewExpr,
    CallGraph,
    ArkParameterRef,
    ArkInstanceFieldRef,
    ClassType,
    ArkNamespace,
} from 'arkanalyzer/lib';
import Logger, { LOG_MODULE_TYPE } from 'arkanalyzer/lib/utils/logger';
import { BaseChecker, BaseMetaData } from '../BaseChecker';
import { Rule, Defects, MatcherCallback } from '../../Index';
import { IssueReport } from '../../model/Defects';
import { DVFG, DVFGNode } from 'arkanalyzer/lib/VFG/DVFG';
import { CALL_DEPTH_LIMIT, getLanguageStr, getLineAndColumn, GlobalCallGraphHelper } from './Utils';
import { ClassCategory } from 'arkanalyzer/lib/core/model/ArkClass';
import { Language } from 'arkanalyzer/lib/core/model/ArkFile';

const logger = Logger.getLogger(LOG_MODULE_TYPE.HOMECHECK, 'InteropObjectLiteralCheck');
const gMetaData: BaseMetaData = {
    severity: 1,
    ruleDocPath: '',
    description: '',
};

const d2sRuleId: string = 'arkts-interop-d2s-object-literal';
const ts2sRuleId: string = 'arkts-interop-ts2s-object-literal';

export class InteropObjectLiteralCheck implements BaseChecker {
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
            callback: this.check,
        };
        return [matchBuildCb];
    }

    public check = (scene: Scene): void => {
        this.cg = GlobalCallGraphHelper.getCGInstance(scene);

        this.dvfg = new DVFG(this.cg);
        this.dvfgBuilder = new DVFGBuilder(this.dvfg, scene);

        for (let arkFile of scene.getFiles()) {
            if (arkFile.getLanguage() !== Language.ARKTS1_2) {
                continue;
            }
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

    public processArkMethod(target: ArkMethod, scene: Scene): void {
        const stmts = target.getBody()?.getCfg().getStmts() ?? [];
        for (const stmt of stmts) {
            if (!(stmt instanceof ArkAssignStmt)) {
                continue;
            }
            const rightOp = stmt.getRightOp();
            if (!(rightOp instanceof ArkInstanceOfExpr)) {
                continue;
            }
            if (!this.visited.has(target)) {
                this.dvfgBuilder.buildForSingleMethod(target);
                this.visited.add(target);
            }

            let result: Stmt[] = [];
            let checkAll = { value: true };
            let visited: Set<Stmt> = new Set();
            this.checkFromStmt(stmt, scene, result, checkAll, visited);
            // 对于待检查的instanceof语句，其检查对象存在用字面量赋值的情况，需要判断对象声明时的类型注解的来源，满足interop场景时需在此处告警
            if (result.length > 0) {
                const opType = rightOp.getOp().getType();
                if (!(opType instanceof ClassType)) {
                    continue;
                }
                const opTypeClass = scene.getClass(opType.getClassSignature());
                if (opTypeClass === null || opTypeClass.getCategory() === ClassCategory.OBJECT) {
                    continue;
                }
                if (
                    opTypeClass.getLanguage() === Language.TYPESCRIPT ||
                    opTypeClass.getLanguage() === Language.ARKTS1_1
                ) {
                    this.addIssueReport(stmt, rightOp, result, opTypeClass.getLanguage());
                }
            }
        }
    }

    private checkFromStmt(
        stmt: Stmt,
        scene: Scene,
        res: Stmt[],
        checkAll: { value: boolean },
        visited: Set<Stmt>,
        depth: number = 0
    ): void {
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
            if (this.isObjectLiteral(currentStmt, scene)) {
                res.push(currentStmt);
                continue;
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
                this.processCallsites(callsites);
                this.collectArgDefs(paramIdx, callsites).forEach(d =>
                    this.checkFromStmt(d, scene, res, checkAll, visited, depth + 1)
                );
            }
            current.getIncomingEdge().forEach(e => worklist.push(e.getSrcNode() as DVFGNode));
        }
    }

    private processCallsites(callsites: Stmt[]): void {
        callsites.forEach(cs => {
            const declaringMtd = cs.getCfg().getDeclaringMethod();
            if (!this.visited.has(declaringMtd)) {
                this.dvfgBuilder.buildForSingleMethod(declaringMtd);
                this.visited.add(declaringMtd);
            }
        });
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
        return scene.getClass(classSig)?.getCategory() === ClassCategory.OBJECT;
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
        const getKey = (v: Value): Value | FieldSignature => {
            return v instanceof ArkInstanceFieldRef ? v.getFieldSignature() : v;
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

    private addIssueReport(stmt: Stmt, operand: Value, result: Stmt[], targetLanguage: Language): void {
        const interopRuleId = this.getInteropRule(targetLanguage);
        if (interopRuleId === null) {
            return;
        }
        const severity = this.metaData.severity;
        const warnInfo = getLineAndColumn(stmt, operand);
        let targetLan = getLanguageStr(targetLanguage);

        const resPos: number[] = [];
        result.forEach(stmt => resPos.push(stmt.getOriginPositionInfo().getLineNo()));
        const problem = 'Interop';
        const desc = `instanceof including object literal with class type from ${targetLan} (${interopRuleId})`;
        let defects = new Defects(
            warnInfo.line,
            warnInfo.startCol,
            warnInfo.endCol,
            problem,
            desc,
            severity,
            this.rule.ruleId,
            warnInfo.filePath,
            this.metaData.ruleDocPath,
            true,
            false,
            false
        );
        this.issues.push(new IssueReport(defects, undefined));
    }

    private getInteropRule(targetLanguage: Language): string | null {
        if (targetLanguage === Language.TYPESCRIPT) {
            return ts2sRuleId;
        }
        if (targetLanguage === Language.ARKTS1_1) {
            return d2sRuleId;
        }
        return null;
    }
}
