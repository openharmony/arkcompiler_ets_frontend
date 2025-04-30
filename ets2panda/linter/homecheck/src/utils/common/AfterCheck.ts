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

import { FileReports } from '../../Index';
import { CheckEntry } from './CheckEntry';

export async function processAfterCheck(checkEntry: CheckEntry): Promise<void> {
    // 按规则维度统计告警信息，按文件维度汇总告警信息
    const fileIssues = checkEntry.sortIssues();
    let fileReports: FileReports[] = [];
    if (checkEntry.projectConfig.fix === 'true') {
        // 代码修复
        fileReports = checkEntry.codeFix(fileIssues);
    } else {
        // 转换输出格式，去掉fix相关信息
        fileIssues.forEach((fileIssue) => {
            fileReports.push({ filePath: fileIssue.filePath, defects: fileIssue.issues.map(issue => issue.defect) });
        });
    }
    // 发送消息
    await checkEntry.message?.sendResult(fileReports, checkEntry.projectConfig.reportDir);
}
