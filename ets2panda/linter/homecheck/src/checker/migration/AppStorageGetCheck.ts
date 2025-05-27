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
    ArkInstanceInvokeExpr,
    ArkMethod,
    ArkStaticInvokeExpr,
    CallGraph,
    CallGraphBuilder,
    Stmt,
    Value,
} from 'arkanalyzer/lib';
import Logger, { LOG_MODULE_TYPE } from 'arkanalyzer/lib/utils/logger';
import { BaseChecker, BaseMetaData } from '../BaseChecker';
import { Rule, Defects, ClassMatcher, MethodMatcher, MatcherTypes, MatcherCallback } from '../../Index';
import { IssueReport } from '../../model/Defects';
import { CALL_DEPTH_LIMIT, CALLBACK_METHOD_NAME, CallGraphHelper } from './Utils';
import { WarnInfo } from '../../utils/common/Utils';

const logger = Logger.getLogger(LOG_MODULE_TYPE.HOMECHECK, 'AppStorageGetCheck');
const gMetaData: BaseMetaData = {
    severity: 1,
    ruleDocPath: '',
    description:
        'Get State of AppStorage in component build function, it will update UI interface when the state of AppStorage is changed',
};

const APP_STORAGE_STR = 'AppStorage';
const API_SET: Set<string> = new Set<string>(['has', 'get', 'keys', 'size']);

export class AppStorageGetCheck implements BaseChecker {
    readonly metaData: BaseMetaData = gMetaData;
    public rule: Rule;
    public defects: Defects[] = [];
    public issues: IssueReport[] = [];

    private classMatcher: ClassMatcher = {
        matcherType: MatcherTypes.CLASS,
        hasViewTree: true,
    };

    private buildMatcher: MethodMatcher = {
        matcherType: MatcherTypes.METHOD,
        class: [this.classMatcher],
        name: ['build'],
    };

    public registerMatchers(): MatcherCallback[] {
        const matchBuildCb: MatcherCallback = {
            matcher: this.buildMatcher,
            callback: this.check,
        };
        return [matchBuildCb];
    }

    public check = (targetMtd: ArkMethod): void => {
        const scene = targetMtd.getDeclaringArkFile().getScene();
        let callGraph = CallGraphHelper.getCGInstance(scene);
        let callGraphBuilder = new CallGraphBuilder(callGraph, scene);
        callGraphBuilder.buildClassHierarchyCallGraph([targetMtd.getSignature()]);

        this.checkMethod(targetMtd, callGraph);
    };

    private checkMethod(targetMtd: ArkMethod, cg: CallGraph, depth: number = 0): void {
        if (depth > CALL_DEPTH_LIMIT) {
            return;
        }
        const stmts = targetMtd.getBody()?.getCfg().getStmts() ?? [];
        for (const stmt of stmts) {
            this.checkAppStorageGet(stmt);
            const invokeExpr = stmt.getInvokeExpr();
            if (invokeExpr && invokeExpr instanceof ArkInstanceInvokeExpr) {
                if (
                    CALLBACK_METHOD_NAME.includes(
                        invokeExpr.getMethodSignature().getMethodSubSignature().getMethodName()
                    )
                ) {
                    continue;
                }
            }
            let callsite = cg.getCallSiteByStmt(stmt);
            callsite.forEach(cs => {
                let callee = cg.getArkMethodByFuncID(cs.calleeFuncID);
                if (callee) {
                    this.checkMethod(callee, cg, depth + 1);
                }
            });
        }
    }

    private checkAppStorageGet(stmt: Stmt): void {
        let invokeExpr = stmt.getInvokeExpr();
        if (!(invokeExpr instanceof ArkStaticInvokeExpr)) {
            return;
        }
        const methodSig = invokeExpr.getMethodSignature();
        if (methodSig.getDeclaringClassSignature().getClassName() !== APP_STORAGE_STR) {
            return;
        }
        if (!API_SET.has(methodSig.getMethodSubSignature().getMethodName())) {
            return;
        }
        this.addIssueReport(stmt, invokeExpr);
    }

    private addIssueReport(stmt: Stmt, operand: Value): void {
        const severity = this.rule.alert ?? this.metaData.severity;
        const warnInfo = this.getLineAndColumn(stmt, operand);
        const problem = 'AppStorageSpecChanged';
        const desc = `${this.metaData.description} (${this.rule.ruleId.replace('@migration/', '')})`;
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

    private getLineAndColumn(stmt: Stmt, operand: Value): WarnInfo {
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
