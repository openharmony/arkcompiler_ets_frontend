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
    ArkAssignStmt,
    ArkClass,
    ArkFile,
    ArkIfStmt,
    ArkInstanceFieldRef,
    ArkInstanceInvokeExpr,
    ArkMethod,
    ClassType,
    FunctionType,
    Local,
    Stmt,
    Value,
} from 'arkanalyzer';
import Logger, { LOG_MODULE_TYPE } from 'arkanalyzer/lib/utils/logger';
import { BaseChecker, BaseMetaData } from '../BaseChecker';
import { Rule, Defects, MatcherTypes, MethodMatcher, MatcherCallback, ClassMatcher } from '../../Index';
import { IssueReport } from '../../model/Defects';
import { ClassCategory } from 'arkanalyzer/lib/core/model/ArkClass';

const logger = Logger.getLogger(LOG_MODULE_TYPE.HOMECHECK, 'NoMethodOverridingFieldCheck');
const gMetaData: BaseMetaData = {
    severity: 1,
    ruleDocPath: '',
    description: '',
};

export class NoMethodOverridingFieldCheck implements BaseChecker {
    readonly metaData: BaseMetaData = gMetaData;
    public rule: Rule;
    public defects: Defects[] = [];
    public issues: IssueReport[] = [];

    private classMetcher: ClassMatcher = {
        matcherType: MatcherTypes.CLASS,
        ClassCategory: [ClassCategory.CLASS],
    };

    public registerMatchers(): MatcherCallback[] {
        const methodCb: MatcherCallback = {
            matcher: this.classMetcher,
            callback: this.check,
        };
        return [methodCb];
    }

    public check = (target: ArkClass): void => {
        const interfaces = target.getAllHeritageClasses().filter(c => c.getCategory() === ClassCategory.INTERFACE);
        for (const i of interfaces) {
            const fields = i
                .getFields()
                .filter(f => f.getType() instanceof FunctionType)
                .map(f => f.getName());
            fields.forEach(f => {
                const method = target.getMethodWithName(f);
                if (method) {
                    // record class
                    // console.log(`111`)
                }
            });
        }
    };
}
