/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

import * as fs from 'node:fs';
import * as path from 'node:path';

const TS_EXT = ".ts";
const D_TS_EXT = '.d.ts';
const TSX_EXT = ".tsx";
const ETS_EXT = ".ets";

class Mode {
  static DEFAULT = 1;
  static AUTOFIX = 2;
  static ARKTS2 = 3;
  static MIGRATE = 4;
}

const LINT_RESULT_EXT = [];
LINT_RESULT_EXT[Mode.DEFAULT] = '.json';
LINT_RESULT_EXT[Mode.AUTOFIX] = '.autofix.json';
LINT_RESULT_EXT[Mode.ARKTS2] = '.arkts2.json';
LINT_RESULT_EXT[Mode.MIGRATE] = '.migrate.json';
const DIFF_EXT = '.diff';
const RESULTS_DIR = 'results';
const TEST_ARGS_EXT = '.args.json';
const MIGRATE_RESULT_SUFFIX = '.migrate';

let testDirs = [];

// forces to update all tests regardless of whether there was diff in a test result
let force_update = false;

for (let arg of process.argv.slice(2)) {
  if (arg === '--force')
    force_update = true;
  else
    testDirs.push(arg);
}

const DEFAULT_COPYRIGHT = [
  "Copyright (c) 2025 Huawei Device Co., Ltd.",
  "Licensed under the Apache License, Version 2.0 (the 'License');",
  "you may not use this file except in compliance with the License.",
  "You may obtain a copy of the License at",
  "",
  "http://www.apache.org/licenses/LICENSE-2.0",
  "",
  "Unless required by applicable law or agreed to in writing, software",
  "distributed under the License is distributed on an 'AS IS' BASIS,",
  "WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.",
  "See the License for the specific language governing permissions and",
  "limitations under the License."
];

function readJsonFile(filePath) {
  try {
    let resultFile = fs.readFileSync(filePath).toString();
    return JSON.parse(resultFile);
  } catch (error) {
    return undefined;
  }
}

function updateTestFile(testDir, testFile) {
  let testModes = [Mode.DEFAULT];

  const testArgsFile = path.join(testDir, testFile + TEST_ARGS_EXT);
  if (fs.existsSync(testArgsFile)) {
    const testArgs = readJsonFile(testArgsFile);
    if (testArgs?.mode?.autofix !== undefined) testModes.push(Mode.AUTOFIX);
    if (testArgs?.mode?.arkts2 !== undefined) testModes.push(Mode.ARKTS2);
    if (testArgs?.mode?.migrate !== undefined) testModes.push(Mode.MIGRATE);
  }

  for (const mode of testModes) {
    updateTest(testDir, testFile, mode);
  }
}

function updateTest(testDir, testFile, mode) {
  updateLintResult(testDir, testFile, mode);
  if (mode === Mode.MIGRATE) {
    updateMigrateResult(testDir, testFile);
  }
}

function updateLintResult(testDir, testFile, mode) {
  let resultExt = LINT_RESULT_EXT[mode];
  let resultFileWithExt = testFile + resultExt;
  let resultFilePath = path.join(testDir, resultFileWithExt);

  // Update test result when:
  // - '.diff' exists
  // - expected '.json' for specified test mode doesn't exist
  // - 'force' option is enabled
  if (fs.existsSync(resultFilePath) && !fs.existsSync(path.join(testDir, RESULTS_DIR, resultFileWithExt + DIFF_EXT)) && !force_update) {
    return;
  }

  let expectedResult = readJsonFile(resultFilePath);

  const copyright = expectedResult?.copyright ?? DEFAULT_COPYRIGHT;

  let actualResult = readJsonFile(path.join(testDir, RESULTS_DIR, resultFileWithExt));
  if (!actualResult || !actualResult.result) {
    console.log(`Failed to update ${resultFileWithExt}: couldn't process ACTUAL result file.`);
    return;
  }

  // Write file with actual test results.
  try {
    const newResultJSON = JSON.stringify({ copyright, result: actualResult.result }, null, 4);
    fs.writeFileSync(resultFilePath, newResultJSON);
  }
  catch (e) {
    console.log(`Failed to update ${resultFileWithExt}: ${e.message || e}`);
    return;
  }


  console.log(`Updated ${resultFileWithExt}`);
}

function updateMigrateResult(testDir, testFile) {
  let resultExt = MIGRATE_RESULT_SUFFIX + path.extname(testFile);
  let resultFileWithExt = testFile + resultExt;
  let resultFilePath = path.join(testDir, resultFileWithExt);

  // Update test result when:
  // - '.diff' exists
  // - expected result file doesn't exist
  // - 'force' option is enabled
  if (fs.existsSync(resultFilePath) && !fs.existsSync(path.join(testDir, RESULTS_DIR, resultFileWithExt + DIFF_EXT)) && !force_update) {
    return;
  }

  try {
    const actualResultFilePath = path.join(testDir, RESULTS_DIR, resultFileWithExt);
    fs.copyFileSync(actualResultFilePath, resultFilePath);
  }
  catch (e) {
    console.log(`Failed to update ${resultFileWithExt}: ${e.message || e}`);
    return;
  }

  console.log(`Updated ${resultFileWithExt}`);
}

for (let testDir of testDirs) {
  if (!fs.existsSync(path.join(testDir, RESULTS_DIR))) continue;

  // Get tests from test directory.
  let testFiles = fs.readdirSync(testDir).filter(x => {
    const file = x.trimEnd();
    return (
      (file.endsWith(TS_EXT) && !file.endsWith(D_TS_EXT)) ||
        file.endsWith(TSX_EXT) ||
        file.endsWith(ETS_EXT)
      ) && !file.endsWith(MIGRATE_RESULT_SUFFIX + path.extname(file))
  });

  if (!testFiles) continue;

  // Update result for each test:
  for (let testFile of testFiles) {
    updateTestFile(testDir, testFile);
  }
}