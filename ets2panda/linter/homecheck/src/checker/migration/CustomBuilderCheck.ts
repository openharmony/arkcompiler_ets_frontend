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

import { ArkAssignStmt, Scene, Local, Stmt, Type, ArkMethod, AliasType, AbstractInvokeExpr, Value } from "arkanalyzer";
import Logger, { LOG_MODULE_TYPE } from 'arkanalyzer/lib/utils/logger';
import { BaseChecker, BaseMetaData } from "../BaseChecker";
import { Rule, Defects, MatcherTypes, MatcherCallback, MethodMatcher } from "../../Index";
import { IssueReport } from "../../model/Defects";

const logger = Logger.getLogger(LOG_MODULE_TYPE.HOMECHECK, 'CustomBuilderCheck');
const gMetaData: BaseMetaData = {
    severity: 1,
    ruleDocPath: "",
    description: 'The CustomBuilder type parameter only accepts functions annotated with @Builder.'
};

export class CustomBuilderCheck implements BaseChecker {
    readonly metaData: BaseMetaData = gMetaData;
    public rule: Rule;
    public defects: Defects[] = [];
    public issues: IssueReport[] = [];

    private buildMatcher: MethodMatcher = {
        matcherType: MatcherTypes.METHOD
    };

    public registerMatchers(): MatcherCallback[] {
        const matchBuildCb: MatcherCallback = {
            matcher: this.buildMatcher,
            callback: this.check
        };
        return [matchBuildCb];
    }

    public check = (target: ArkMethod): void => {
        const scene = target.getDeclaringArkFile().getScene();
        const stmts = target.getBody()?.getCfg().getStmts() ?? [];
        let locals = new Set<Local>();
        for (const stmt of stmts) {
            const local = this.isCallToBuilder(stmt, scene);
            if (local) {
                locals.add(local);
                continue;
            }
            const usage = this.isPassToCustomBuilder(stmt, locals);
            if (usage) {
                this.addIssueReport(usage.getDeclaringStmt()!, usage);
            }
        }
    };

    private isCallToBuilder(stmt: Stmt, scene: Scene): Local | undefined {
        if (!(stmt instanceof ArkAssignStmt)) {
            return undefined;
        }
        const leftOp = stmt.getLeftOp();
        if (!(leftOp instanceof Local)) {
            return undefined;
        }
        const rightOp = stmt.getRightOp();
        if (!(rightOp instanceof AbstractInvokeExpr)) {
            return undefined;
        }
        const method = scene.getMethod(rightOp.getMethodSignature());
        if (method && method.hasBuilderDecorator()) {
            return leftOp;
        }
        return undefined;
    }

    private isCumtomBuilderTy(ty: Type) {
        return ty instanceof AliasType && ty.getName() === 'CustomBuilder';
    }

    private isPassToCustomBuilder(stmt: Stmt, locals: Set<Local>): Local | undefined {
        if (stmt instanceof ArkAssignStmt) {
            if (!this.isCumtomBuilderTy(stmt.getLeftOp().getType())) {
                return undefined;
            }
            const rightOp = stmt.getRightOp();
            if (rightOp instanceof Local && locals.has(rightOp)) {
                return rightOp;
            }
        }
        const invokeExpr = stmt.getInvokeExpr();
        if (invokeExpr) {
            const paramTys = invokeExpr.getMethodSignature().getMethodSubSignature().getParameterTypes();
            const args = invokeExpr.getArgs();
            for (let i = 0; i < paramTys.length && i < args.length; ++i) {
                if (!this.isCumtomBuilderTy(paramTys[i])) {
                    continue;
                }
                const arg = args[i];
                if (arg instanceof Local && locals.has(arg)) {
                    return arg;
                }
            }
        }
        return undefined;
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