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

import { CheckEntry } from '../../utils/common/CheckEntry';

export interface ProblemInfo {
    line: number;
    column: number,
    endLine: number;
    endColumn: number;
    start?: number;
    end?: number;
    type?: string;
    severity: number;
    problem: string;
    suggest: string;
    rule: string;
    ruleTag: number;
    autofixable?: boolean;
    aotufix?: AutoFix[];
    autofixTitle?: string;
}

export interface AutoFix {
    replacementText: string;
    start: number;
    end: number;
}

export async function exportIssues(checkEntry: CheckEntry): Promise<Map<string, ProblemInfo[]>> {
    let result = new Map<string, ProblemInfo[]>();
    checkEntry.sortIssues().forEach(fileIssues => {
        fileIssues.issues.forEach(issueReport => {
            const defect = issueReport.defect;
            const problemInfo: ProblemInfo = {
                line: defect.reportLine,
                column: defect.reportColumn,
                endLine: defect.reportLine,
                endColumn: defect.reportColumn,
                severity: defect.severity,
                problem: defect.problem,
                suggest: '',
                rule: defect.description,
                ruleTag: -1,
                autofixable: false
            }
            const filePath = defect.mergeKey.split('%')[0];
            const problems = result.get(filePath) || [];
            problems.push(problemInfo);
            result.set(filePath, problems);
        });
    });
    return result;
}