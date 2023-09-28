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

import * as fs from "fs";

const TS_EXT = ".ts";
const TSX_EXT = ".tsx";
const JSON_EXT = ".json"
const STRICT_EXT = ".strict";
const RELAX_EXT = ".relax";

function readTestFile(filePath) {
    try {
        let resultFile = fs.readFileSync(filePath).toString();
        return JSON.parse(resultFile);
    } catch (error) {
        return undefined;
    }
}

function updateTest(testFile, strictMode) {
    let resultExt = (strictMode ? STRICT_EXT : RELAX_EXT) + JSON_EXT;
    let testFileWithExt = testFile + resultExt;

    let expectedResult = readTestFile(testFileWithExt);
    if (!expectedResult || !expectedResult.copyright) {
        console.log(`Failed to update ${testFileWithExt}: couldn't read EXPECTED result file.`);
        return;
    }

    let actualResult = readTestFile("results/" + testFileWithExt);
    if (!actualResult || !actualResult.nodes) {
        console.log(`Failed to update ${testFileWithExt}: couldn't read ACTUAL result file.`);
        return;
    }

    // Write file with actual test results.
    let newResultJSON = JSON.stringify({ copyright: expectedResult.copyright, nodes: actualResult.nodes }, null, 4);
    fs.writeFileSync(testFileWithExt, newResultJSON);

    console.log(`Updated ${testFileWithExt}`);
}

if (!fs.existsSync("results")) {
    console.log("The 'results' dir does not exist!");
    process.exit(0);
}

// Get tests from test directory.
let testFiles = fs.readdirSync(".").filter(x => x.trimEnd().endsWith(TS_EXT) || x.trimEnd().endsWith(TSX_EXT));

if (!testFiles || testFiles.length == 0) {
    console.log("No tests to update.");
    process.exit(0);
}

// Update result for each test for Strict and Relax modes:
for (let testFile of testFiles) {
    updateTest(testFile, false);
    updateTest(testFile, true);
}