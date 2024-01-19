/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import * as fs from 'fs';

const ARK_TS_ISSUES_PREFIX = 'ArkTS';
const ARK_TS_ISSUES_ERROR_CATEGORY = 'ArkTS Migration Errors';

interface DefectInfo {
  // warn: 1; error: 2;
  severity: number;
  description: string;
  mergeKey: string;
  reportLine: number;
  reportColumn: number;
  ruleId: string | null;
  ruleDocPath: string | null;
  category: string | null;
  fixable: boolean;
  fixKey: string;
}

interface FileDefectInfo {
  defects: DefectInfo[];
  output: string | undefined;
  filePath: string;
}

type ReportJson = FileDefectInfo[];

interface ArkTsIssueType {
  description: string;
  type: string;
  count: number;
}

interface Statistics {
  totalErrors: number;
  totalWarnings: number;
  linesWithErrors: number;
  linesWithWarnings: number;
  issues: Map<number, ArkTsIssueType>;
}

function isError(defectInfo: DefectInfo): boolean {
  return defectInfo.category === ARK_TS_ISSUES_ERROR_CATEGORY;
}

function fillIssueInfo(statistics: Statistics, defectInfo: DefectInfo): void {
  const recipeNo = parseInt(
    defectInfo.ruleDocPath.substring('docs/recipe'.length, defectInfo.ruleDocPath.length - '.md'.length)
  );
  const issueInfo = statistics.issues.get(recipeNo);
  if (!issueInfo) {
    statistics.issues.set(recipeNo, {
      description: defectInfo.description,
      type: isError(defectInfo) ? 'error' : 'warn',
      count: 1
    });
  } else {
    issueInfo.count += 1;
  }
}

function parse(reportJson: ReportJson): Statistics {
  const statistics: Statistics = {
    totalErrors: 0,
    totalWarnings: 0,
    linesWithErrors: 0,
    linesWithWarnings: 0,
    issues: new Map()
  };

  for (const fileInfo of reportJson) {
    const linesWithErrors: Set<number> = new Set();
    const linesWithWarnings: Set<number> = new Set();

    for (const defectInfo of fileInfo.defects) {
      // count only issues from ArkTS Linter
      if (!defectInfo.category.startsWith(ARK_TS_ISSUES_PREFIX)) {
        continue;
      }

      fillIssueInfo(statistics, defectInfo);

      if (isError(defectInfo)) {
        statistics.totalErrors += 1;
        linesWithErrors.add(defectInfo.reportLine);
      } else {
        statistics.totalWarnings += 1;
        linesWithWarnings.add(defectInfo.reportLine);
      }
    }
    statistics.linesWithErrors += linesWithErrors.size;
    statistics.linesWithWarnings += linesWithWarnings.size;
  }

  return statistics;
}

function read(filePath: string): ReportJson {
  return JSON.parse(fs.readFileSync(filePath, { encoding: 'utf8', flag: 'r' }));
}

function main(): void {
  if (process.argv.length < 3) {
    console.error('Path to input json was not provided, exiting');
    process.exit(1);
  }
  console.log(parse(read(process.argv[2])));
}

/*
 * file is stored in project's directory under the following path:
 * <PROJECT_ROOT_DIR>/.idea/code-linter/eslintAgent/output.json
 */
main();
