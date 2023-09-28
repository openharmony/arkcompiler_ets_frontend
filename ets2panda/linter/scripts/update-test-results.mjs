/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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
const TSX_EXT = ".tsx";
const D_TS_EXT = '.d.ts';

class Mode {
    static STRICT = 1;
    static RELAX = 2;
    static AUTOFIX = 3
}

const RESULT_EXT = [];
RESULT_EXT[Mode.STRICT] = '.strict.json';
RESULT_EXT[Mode.RELAX] = '.relax.json';
RESULT_EXT[Mode.AUTOFIX] = '.autofix.json';
const AUTOFIX_SKIP_EXT = '.autofix.skip';
const DIFF_EXT = '.diff';
const RESULTS_DIR = 'results'

let testDirs = [];

// forces to update all tests regardless of whether there was diff in a test result
const force_update = false;

for (let arg of process.argv.slice(2)) {
    if (arg === '--force')
        force_update = true;
    else
        testDirs.push(arg);
}

const DEFAULT_COPYRIGHT =  [
    "Copyright (c) 2023-2023 Huawei Device Co., Ltd.",
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

function readTestFile(filePath) {
    try {
        let resultFile = fs.readFileSync(filePath).toString();
        return JSON.parse(resultFile);
    } catch (error) {
        return undefined;
    }
}

function updateTest(testDir, testFile, mode) {
    let resultExt = RESULT_EXT[mode];
    let testFileWithExt = testFile + resultExt;

    // Do not update autofix result if test is skipped
    if (mode === Mode.AUTOFIX && fs.existsSync(path.join(testDir, testFileWithExt + AUTOFIX_SKIP_EXT))) {
        return;
    }

    // Update test result when 'diff' exists or the 'force' option is enabled.
    if (!fs.existsSync(path.join(testDir, RESULTS_DIR, testFileWithExt + DIFF_EXT)) && !force_update) {
        return;
    }

    let expectedResult = readTestFile(path.join(testDir, testFileWithExt));

    const copyright = expectedResult?.copyright ?? DEFAULT_COPYRIGHT;

    let actualResult = readTestFile(path.join(testDir, RESULTS_DIR, testFileWithExt));
    if (!actualResult || !actualResult.nodes) {
        console.log(`Failed to update ${testFileWithExt}: couldn't read ACTUAL result file.`);
        return;
    }

    // Write file with actual test results.
    let newResultJSON = JSON.stringify({ copyright, nodes: actualResult.nodes }, null, 4);
    fs.writeFileSync(path.join(testDir, testFileWithExt), newResultJSON);

    console.log(`Updated ${testFileWithExt}`);
}

for (let testDir of testDirs) {
    if (!fs.existsSync(path.join(testDir, RESULTS_DIR))) continue;

    // Get tests from test directory.
    let testFiles = fs.readdirSync(testDir).filter(x =>
        (x.trimEnd().endsWith(TS_EXT) && !x.trimEnd().endsWith(D_TS_EXT)) || x.trimEnd().endsWith(TSX_EXT));

    if (!testFiles) continue;

    // Update result for each test for Strict and Relax modes:
    for (let testFile of testFiles) {
        updateTest(testDir, testFile, Mode.RELAX);
        updateTest(testDir, testFile, Mode.STRICT);
        updateTest(testDir, testFile, Mode.AUTOFIX);
    }
}