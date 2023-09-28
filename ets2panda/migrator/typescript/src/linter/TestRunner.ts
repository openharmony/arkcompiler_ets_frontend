/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

import { TypeScriptLinter } from "./TypeScriptLinter";
import { lint } from "./LinterRunner";
import { parseCommandLine } from "./CommandLineParser";
import * as fs from "node:fs";

const TS_EXT = ".ts"
const TSX_EXT = ".tsx"
const JSON_EXT = ".json"
const STRICT_EXT = ".strict";
const RELAX_EXT = ".relax";
const TEST_DIR = "test/linter";

const TAB = "    ";

interface TestNodeInfo {
    line: number,
    column: number,
    problem: string
}

function runTests(): number {
    let hasComparisonFailures = false;

    // Set the IDE mode manually to enable storing information
    // about found bad nodes and also disable the log output.  
    TypeScriptLinter.IDE_mode = true;

    // Get tests from test directory
    let testFiles: string[] = fs.readdirSync(TEST_DIR).filter(x => x.trimEnd().endsWith(TS_EXT) || x.trimEnd().endsWith(TSX_EXT));

    if (!testFiles || testFiles.length == 0) {
        console.log("No tests to run!");
        process.exit(0);
    }

    let passed = 0, failed = 0;

    // Run each test in Strict and Relax mode:
    for (let testFile of testFiles) {
        let result = runTest(testFile, false);
        if (result) failed++;
        else passed++;
        hasComparisonFailures ||= result;

        result = runTest(testFile, true);
        if (result) failed++;
        else passed++;
        hasComparisonFailures ||= result;
    }

    console.log(`\nSUMMARY: ${passed + failed} total, ${passed} passed, ${failed} failed.`);
    process.exit(hasComparisonFailures ? -1 : 0);
}

function runTest(testFile: string, strictMode: boolean): boolean {
    let testFailed = false;

    console.log(`Running test ${testFile} (${strictMode ? "Strict" : "Relax"} mode)`);

    // Clear node info collection from the previous test run.
    TypeScriptLinter.badNodeInfos = [];

    // Configure test parameters and run linter.
    let args: string[] = [ TEST_DIR + '/' + testFile ];
    if (strictMode) args.push("--strict");
    lint(parseCommandLine(args));

    let resultExt = (strictMode ? STRICT_EXT : RELAX_EXT) + JSON_EXT;
    let testResultFileName = testFile + resultExt;

    // Get list of bad nodes from the current run.
    let resultNodes: TestNodeInfo[] = TypeScriptLinter.badNodeInfos.map<TestNodeInfo>(x => ({ line: x.line, column: x.column, problem: x.problem }));
    
    // Read file with expected test result.
    let expectedResult: { nodes: TestNodeInfo[] };
    try {
        let expectedResultFile = fs.readFileSync(TEST_DIR + '/' + testResultFileName).toString();
        expectedResult = JSON.parse(expectedResultFile);

        if (!expectedResult || !expectedResult.nodes || expectedResult.nodes.length !== resultNodes.length) {
            testFailed = true;
        } else {
            // Compare expected and actual results.    
            for (let i = 0; i < resultNodes.length; i++) {
                if (resultNodes[i].line !== expectedResult.nodes[i].line
                        || resultNodes[i].column !== expectedResult.nodes[i].column
                        || resultNodes[i].problem !== expectedResult.nodes[i].problem) {
                    testFailed = true;
                    break;
                }
            }
        }

        if (testFailed) {
            console.log(`${TAB}Test failed. Expected and actual results differ.`);
        }
    } catch (error) {
        testFailed = true;
        console.log(`${TAB}Test failed. ${error.message ?? error}`);
    }

    // Write file with actual test results.
    let actualResultsDir = TEST_DIR + "/results";
    if (!fs.existsSync(actualResultsDir)) {
        fs.mkdirSync(actualResultsDir);
    }
    let actualResultJSON = JSON.stringify({ nodes: resultNodes }, null, 4);
    fs.writeFileSync(actualResultsDir + '/' + testFile + resultExt, actualResultJSON);

    return testFailed;
}

runTests();