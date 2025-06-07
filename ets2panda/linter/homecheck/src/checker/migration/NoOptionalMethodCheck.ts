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

import { ArkClass, ArkMethod } from 'arkanalyzer';
import Logger, { LOG_MODULE_TYPE } from 'arkanalyzer/lib/utils/logger';
import { BaseChecker, BaseMetaData } from '../BaseChecker';
import { Rule, Defects, MatcherTypes, MatcherCallback, ClassMatcher } from '../../Index';
import { IssueReport } from '../../model/Defects';

const logger = Logger.getLogger(LOG_MODULE_TYPE.HOMECHECK, 'NoOptionalMethodCheck');
const gMetaData: BaseMetaData = {
    severity: 1,
    ruleDocPath: '',
    description: '',
};

export class NoOptionalMethodCheck implements BaseChecker {
    readonly metaData: BaseMetaData = gMetaData;
    public rule: Rule;
    public defects: Defects[] = [];
    public issues: IssueReport[] = [];

    private classMetcher: ClassMatcher = {
        matcherType: MatcherTypes.CLASS,
    };

    public registerMatchers(): MatcherCallback[] {
        const classCb: MatcherCallback = {
            matcher: this.classMetcher,
            callback: this.check,
        };
        return [classCb];
    }

    public check = (target: ArkClass): void => {
        target
            .getMethods()
            .filter(m => m.getQuestionToken())
            .forEach(m => {
                const posInfo = this.getMethodPos(m);
                this.addIssueReport(posInfo);
            });
    };

    private addIssueReport(warnInfo: { line: number; startCol: number; endCol: number; filePath: string }): void {
        const problem = '';
        const severity = this.rule.alert ?? this.metaData.severity;
        let defects = new Defects(
            warnInfo.line,
            warnInfo.startCol,
            warnInfo.endCol,
            problem,
            this.metaData.description,
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

    private getMethodPos(cls: ArkMethod): { line: number; startCol: number; endCol: number; filePath: string } {
        const line = cls.getLineCol() ?? -1;
        const startCol = cls.getColumn() ?? -1;
        const endCol = startCol;
        const arkFile = cls.getDeclaringArkFile();
        if (arkFile) {
            return { line, startCol, endCol, filePath: arkFile.getFilePath() };
        } else {
            logger.debug('ArkFile is null.');
            return { line, startCol, endCol, filePath: '' };
        }
    }
}
