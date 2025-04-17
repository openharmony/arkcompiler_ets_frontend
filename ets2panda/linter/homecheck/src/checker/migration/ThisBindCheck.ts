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

import { ArkAssignStmt, ArkIfStmt, ArkInstanceFieldRef, ArkInstanceInvokeExpr, ArkMethod, ClassType, FunctionType, Local, Stmt, Value, Scene } from "arkanalyzer";
import Logger, { LOG_MODULE_TYPE } from 'arkanalyzer/lib/utils/logger';
import { BaseChecker, BaseMetaData } from "../BaseChecker";
import { Rule, Defects, MatcherTypes, MethodMatcher, MatcherCallback } from "../../Index";
import { IssueReport } from "../../model/Defects";

const logger = Logger.getLogger(LOG_MODULE_TYPE.HOMECHECK, 'ThisBindCheck');

const ARKTS_RULE_ID = '@migration/arkts-instance-method-bind-this'
const arktsMetaData: BaseMetaData = {
    severity: 1,
    ruleDocPath: "",
    description: 'Instance method shall bind the \'this\' by default.'
};

const ARKUI_RULE_ID = '@migration/arkui-buildparam-passing';
const arkuiMetaData: BaseMetaData = {
    severity: 1,
    ruleDocPath: "",
    description: 'Instance method shall bind the \'this\' by default.'
};

export class ThisBindCheck implements BaseChecker {
    readonly metaData: BaseMetaData = arktsMetaData;
    public rule: Rule;
    public defects: Defects[] = [];
    public issues: IssueReport[] = [];

    private methodMatcher: MethodMatcher = {
        matcherType: MatcherTypes.METHOD
    };

    public registerMatchers(): MatcherCallback[] {
        const methodCb: MatcherCallback = {
            matcher: this.methodMatcher,
            callback: this.check
        }
        return [methodCb];
    }

    public check = (targetMtd: ArkMethod) => {
        const file = targetMtd.getDeclaringArkFile();
        if (file.getName().includes("test.ets")) {
            return;
        }
        const scene = file.getScene();
        const stmts = targetMtd.getBody()?.getCfg().getStmts() ?? [];
        for (let i = 0; i < stmts.length; ++i) {
            const stmt = stmts[i];
            // const method = a.foo
            if (!(stmt instanceof ArkAssignStmt)) {
                continue;
            }
            const rightOp = stmt.getRightOp();
            if (!(rightOp instanceof ArkInstanceFieldRef)) {
                continue;
            }
            const base = rightOp.getBase();
            const classTy = base.getType();
            if (!(classTy instanceof ClassType)) {
                continue;
            }
            if (!(rightOp.getFieldSignature().getType() instanceof FunctionType)) {
                continue;
            }
            const klass = scene.getClass(classTy.getClassSignature());
            const method = klass?.getMethodWithName(rightOp.getFieldName());
            if (!method || !method.getCfg() || !this.useThisInBody(method)) {
                continue;
            }
            if (base.getName() === "this" && targetMtd.isAnonymousMethod()) {
                continue;
            }
            const leftOp = stmt.getLeftOp();
            if (i + 1 >= stmts.length || !this.hasBindThis(leftOp, stmts[i + 1])) {
                if (!this.isSafeUse(leftOp)) {
                    this.addIssueReport(stmt, base, scene);
                }
            }
        }
    }

    private useThisInBody(method: ArkMethod): boolean {
        const thisInstance = (method.getThisInstance() as Local)!;
        return thisInstance.getUsedStmts().length > 0;
    }

    private isSafeUse(v: Value): boolean {
        if (!(v instanceof Local)) {
            return false;
        }

        const users = v.getUsedStmts();
        if (users.length === 0) {
            return false;
        }
        for (const user of users) {
            if (user instanceof ArkIfStmt) {
                const cond = user.getConditionExpr();
                if (v !== cond.getOp1() && v !== cond.getOp2()) {
                    return false;
                }
            } else {
                return false;
            }
        }
        return true;
    }

    private hasBindThis(base: Value, next: Stmt): boolean {
        if (!(next instanceof ArkAssignStmt)) {
            return false;
        }
        const rightOp = next.getRightOp();
        if (rightOp instanceof ArkInstanceFieldRef && rightOp.getBase() === base) {
            // const method = a.foo.name
            return true;
        }
        if (!(rightOp instanceof ArkInstanceInvokeExpr)) {
            return false;
        }
        if (rightOp.getBase() !== base) {
            return false;
        }
        if (rightOp.getMethodSignature().getMethodSubSignature().getMethodName() !== "bind") {
            return false;
        }
        return true;
    }

    private addIssueReport(stmt: ArkAssignStmt, operand: Value, scene: Scene) {
        const assignToBuilderParam = (assign: ArkAssignStmt) => {
            const leftOp = assign.getLeftOp();
            if (!(leftOp instanceof Local)) {
                return false;
            }
            const usedStmts = leftOp.getUsedStmts();
            if (usedStmts.length !== 1) {
                return false;
            }
            const usedStmt = usedStmts[0];
            if (!(usedStmt instanceof ArkAssignStmt)) {
                return false;
            }
            const target = usedStmt.getLeftOp();
            if (!(target instanceof ArkInstanceFieldRef)) {
                return false;
            }
            const baseTy = target.getBase().getType();
            if (!(baseTy instanceof ClassType)) {
                return false;
            }
            const baseClassTy = scene.getClass((baseTy as ClassType).getClassSignature());
            if (!baseClassTy) {
                return false;
            }
            const arkField = baseClassTy.getFieldWithName(target.getFieldName());
            if (!arkField) {
                logger.error("cannot find field while checking if it's an assign to a builder param.");
                return false;
            }
            return arkField.hasBuilderParamDecorator();
        }

        if (assignToBuilderParam(stmt)) {
            this.reportArkUIIssue(stmt, operand);
        } else {
            this.reportArkTSIssue(stmt, operand);
        }
    }

    private reportArkTSIssue(stmt: ArkAssignStmt, operand: Value) {
        const severity = this.rule.alert ?? this.metaData.severity;
        const warnInfo = this.getLineAndColumn(stmt, operand);
        let defects = new Defects(warnInfo.line, warnInfo.startCol, warnInfo.endCol, this.metaData.description, severity, ARKTS_RULE_ID,
            warnInfo.filePath, this.metaData.ruleDocPath, true, false, false);
        this.issues.push(new IssueReport(defects, undefined));
    }

    private reportArkUIIssue(stmt: ArkAssignStmt, operand: Value) {
        const severity = this.rule.alert ?? arkuiMetaData.severity;
        const warnInfo = this.getLineAndColumn(stmt, operand);
        let defects = new Defects(warnInfo.line, warnInfo.startCol, warnInfo.endCol, arkuiMetaData.description, severity, ARKUI_RULE_ID,
            warnInfo.filePath, arkuiMetaData.ruleDocPath, true, false, false);
        this.issues.push(new IssueReport(defects, undefined));
    }

    private getLineAndColumn(stmt: ArkAssignStmt, operand: Value) {
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