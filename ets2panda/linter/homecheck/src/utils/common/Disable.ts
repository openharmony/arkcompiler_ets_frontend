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

import * as fs from 'fs';
import path from 'path';
import { IssueReport } from '../../model/Defects';
import { FileUtils } from '../../Index';
import Logger, { LOG_MODULE_TYPE } from 'arkanalyzer/lib/utils/logger';

const logger = Logger.getLogger(LOG_MODULE_TYPE.HOMECHECK, 'Disable');

export const DisableText = {
    FILE_DISABLE_TEXT: '\/* homecheck-disable *\/',
    NEXT_LINE_DISABLE_TEXT: '\/\/ homecheck-disable-next-line ',
};

export async function filterDisableIssue(lineList: string[], issues: IssueReport[], filePath: string): Promise<IssueReport[]> {
    let filtedIssues: IssueReport[] = [];
    try {
        for (const issue of issues) {
            // @migration/arkui-data-observation规则的自动修复是在定义处，存在跨文件场景
            const actualFilePath = path.normalize(issue.defect.mergeKey.split('%')[0]);
            if (path.normalize(actualFilePath) !== path.normalize(filePath)) {
                if (!fs.existsSync(actualFilePath)) {
                    continue;
                }
                lineList = await FileUtils.readLinesFromFile(actualFilePath);
            }
            // 有些特殊规则允许返回行列号为0
            if (issue.defect.reportLine < 0 || issue.defect.reportLine - 1 > lineList.length) {
                continue;
            }
            const text = lineList[issue.defect.reportLine - 2];
            if (!isDisableIssue(text, issue.defect.ruleId)) {
                filtedIssues.push(issue);
            }
        }
    } catch (e) {
        logger.error(e);
    }
    return filtedIssues;
}

function isDisableIssue(lineText: string, ruleId: string): boolean {
    if (!lineText || lineText.length === 0) {
        return false;
    }

    if (lineText.includes(DisableText.NEXT_LINE_DISABLE_TEXT) && lineText.includes(ruleId)) {
        return true;
    }
    return false;
}
