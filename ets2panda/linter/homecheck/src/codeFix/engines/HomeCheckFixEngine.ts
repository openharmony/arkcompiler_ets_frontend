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

import { ArkFile, SourceFilePrinter } from 'arkanalyzer';
import { FileReports, IssueReport } from '../../model/Defects';
import { Engine } from '../../model/Engine';
import { FunctionFix } from '../../model/Fix';
import path from 'path';
// @ts-ignore
import { removeSync } from 'fs-extra';
import { FileUtils, WriteFileMode } from '../../utils/common/FileUtils';
import Logger, { LOG_MODULE_TYPE } from 'arkanalyzer/lib/utils/logger';
import { FixUtils } from '../../utils/common/FixUtils';

const FIX_OUTPUT_DIR = './fixedCode';

const logger = Logger.getLogger(LOG_MODULE_TYPE.HOMECHECK, 'HomeCheckFixEngine');

export class HomeCheckFixEngine implements Engine {

    constructor() {
        removeSync(FIX_OUTPUT_DIR);
    }

    applyFix(arkFile: ArkFile, issues: IssueReport[]): FileReports {
        let fixPath = '';
        const remainIssues: IssueReport[] = [];
        for (let issue of issues) {
            let fix = issue.fix;
            if (fix === undefined) {
                remainIssues.push(issue);
                continue;
            }
            if (!FixUtils.isFunctionFix(fix)) {
                remainIssues.push(issue);
                continue;
            }
            let functionFix = fix as FunctionFix;
            if (!issue.defect.fixable) {
                remainIssues.push(issue);
                continue;
            }
            if (!functionFix.fix(arkFile, issue.defect.fixKey)) {
                remainIssues.push(issue);
                continue;
            }
            fixPath = path.join(FIX_OUTPUT_DIR, arkFile.getName() + '.fix');
            if (this.arkFileToFile(arkFile, fixPath)) {
                functionFix.fixed = true;
                break;
            }
        }
        return { defects: remainIssues.map((issue => issue.defect)), output: '', filePath: fixPath };
    }

    private arkFileToFile(arkFile: ArkFile, outputPath: string): boolean {
        if (!arkFile) {
            return false;
        }
        const printer = new SourceFilePrinter(arkFile);
        try {
            FileUtils.writeToFile(outputPath, printer.dump(), WriteFileMode.OVERWRITE);
            return true;
        } catch (e) {
            logger.error(e);
            return false;
        }
    }
}
