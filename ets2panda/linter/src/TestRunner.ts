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

import { Logger } from '../lib/Logger';
import { LoggerImpl } from './LoggerImpl';
Logger.init(new LoggerImpl());
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as ts from 'typescript';
import type { CommandLineOptions } from '../lib/CommandLineOptions';
import { lint } from '../lib/LinterRunner';
import { TypeScriptLinter } from '../lib/TypeScriptLinter';
import { InteropTypescriptLinter } from '../lib/InteropTypescriptLinter';
import type { Autofix } from '../lib/autofixes/Autofixer';
import { parseCommandLine } from './CommandLineParser';
import { compileLintOptions } from './Compiler';
import { getEtsLoaderPath } from './LinterCLI';
import { ProblemSeverity } from '../lib/ProblemSeverity';
import type { ProblemInfo } from '../lib/ProblemInfo';

let enableUseRtLogic = true;
let enableCheckTsFile = false;
const TEST_DIR = 'test';
const TAB = '    ';
// initial configuration
const options = ts.readConfigFile('./tsconfig.json', ts.sys.readFile).config.compilerOptions;
const allPath = ['*'];
Object.assign(options, {
  emitNodeModulesFiles: true,
  importsNotUsedAsValues: ts.ImportsNotUsedAsValues.Preserve,
  module: ts.ModuleKind.ES2020,
  moduleResolution: ts.ModuleResolutionKind.NodeJs,
  noEmit: true,
  target: ts.ScriptTarget.ES2021,
  baseUrl: '/',
  paths: {
    '*': allPath
  },
  lib: ['lib.es2021.d.ts'],
  types: [],
  etsLoaderPath: 'null_sdkPath'
});

interface TestNodeInfo {
  line: number;
  column: number;
  endLine: number;
  endColumn: number;
  problem?: string;
  autofix?: Autofix[];
  suggest?: string;
  rule?: string;
  severity?: string;
  exclusive?: string;
}

enum Mode {
  DEFAULT,
  AUTOFIX
}

const RESULT_EXT: string[] = [];
RESULT_EXT[Mode.DEFAULT] = '.json';
RESULT_EXT[Mode.AUTOFIX] = '.autofix.json';
const AUTOFIX_SKIP_EXT = '.autofix.skip';
const ARGS_CONFIG_EXT = '.args.json';
const DIFF_EXT = '.diff';
const testExtensionSts = '.sts';
const testExtensionDSts = '.d.sts';

function runTests(): void {

  /*
   * Set the IDE mode manually to enable storing information
   * about found bad nodes and also disable the log output.
   */
  TypeScriptLinter.ideMode = true;
  TypeScriptLinter.testMode = true;
  InteropTypescriptLinter.ideMode = true;
  InteropTypescriptLinter.testMode = true;

  let hasComparisonFailures = false;
  let passed = 0;
  let failed = 0;
  const testDirs = getParam();
  // Get tests from test directory
  for (const testDir of testDirs) {
    const testFiles: string[] = fs.readdirSync(testDir).filter((x) => {
      return (
        x.trimEnd().endsWith(ts.Extension.Ts) && !x.trimEnd().endsWith(ts.Extension.Dts) ||
        x.trimEnd().endsWith(ts.Extension.Tsx) ||
        x.trimEnd().endsWith(ts.Extension.Ets) ||
        x.trimEnd().endsWith(testExtensionSts) && !x.trimEnd().endsWith(testExtensionDSts)
      );
    });
    Logger.info(`\nProcessing "${testDir}" directory:\n`);
    // Run each test in Default and Autofix mode:
    [passed, failed, hasComparisonFailures] = runTestFiles(testFiles, testDir);
  }
  Logger.info(`\nSUMMARY: ${passed + failed} total, ${passed} passed or skipped, ${failed} failed.`);
  Logger.info(failed > 0 ? '\nTEST FAILED' : '\nTEST SUCCESSFUL');
  process.exit(hasComparisonFailures ? -1 : 0);
}

function runTestFiles(testFiles: string[], testDir: string): [number, number, boolean] {
  let hasComparisonFailures = false;
  let passed = 0;
  let failed = 0;
  for (const testFile of testFiles) {
    let renamed = false;
    let tsName = testFile;
    if (testFile.includes(testExtensionSts)) {
      renamed = true;
      tsName = testFile.replace(testExtensionSts, ts.Extension.Ts);
      fs.renameSync(path.join(testDir, testFile), path.join(testDir, tsName));
    }
    if (runTest(testDir, tsName, Mode.DEFAULT)) {
      failed++;
      hasComparisonFailures = true;
    } else {
      passed++;
    }
    if (runTest(testDir, tsName, Mode.AUTOFIX)) {
      failed++;
      hasComparisonFailures = true;
    } else {
      passed++;
    }
    if (renamed) {
      fs.renameSync(path.join(testDir, tsName), path.join(testDir, testFile));
    }
  }
  return [passed, failed, hasComparisonFailures];
}

function getParam(): string[] {
  let pathArg = null;
  for (const key of process.argv) {
    if (key.includes('-P:')) {
      pathArg = key.replace('-P:', '').split(',');
    }

    if (key.includes('-SDK')) {
      enableUseRtLogic = false;
    }

    if (key.includes('-CheckTs')) {
      enableCheckTsFile = true;
    }
  }

  if (!pathArg?.length) {
    pathArg = [TEST_DIR];
  }
  return pathArg;
}

function parseArgs(testDir: string, testFile: string, mode: Mode): CommandLineOptions {
  // Configure test parameters and run linter.
  const cmdArgs: string[] = [path.join(testDir, testFile)];
  const argsFileName = path.join(testDir, testFile + ARGS_CONFIG_EXT);

  if (fs.existsSync(argsFileName)) {
    const data = fs.readFileSync(argsFileName).toString();
    const args = JSON.parse(data);
    if (args.testMode !== undefined) {
      TypeScriptLinter.testMode = args.testMode;
      InteropTypescriptLinter.testMode = args.testMode;
    }
    if (args.arkts2 === true) {
      cmdArgs.push('--arkts-2');
    }
  }

  if (mode === Mode.AUTOFIX) {
    cmdArgs.push('--autofix');
  }

  if (enableUseRtLogic) {
    cmdArgs.push('--enableUseRtLogic');
  }

  return parseCommandLine(cmdArgs);
}

function compareExpectedAndActual(testDir: string, testFile: string, mode: Mode, resultNodes: TestNodeInfo[]): string {
  // Read file with expected test result.
  let expectedResult: { nodes: TestNodeInfo[] };
  let diff: string = '';
  const resultExt = RESULT_EXT[mode];
  const testResultFileName = testFile + resultExt;
  try {
    const expectedResultFile = fs.readFileSync(path.join(testDir, testResultFileName)).toString();
    expectedResult = JSON.parse(expectedResultFile);

    /**
     * The exclusive field is added to identify whether the use case is exclusive to the RT or SDK
     * RT means the RT exclusive
     * SDK means the SDK exclusive
     * undefined means shared
     */
    expectedResult.nodes = expectedResult?.nodes.filter((x) => {
      return !x?.exclusive || x.exclusive === (enableUseRtLogic ? 'RT' : 'SDK');
    });

    if (!expectedResult?.nodes || expectedResult.nodes.length !== resultNodes.length) {
      const expectedResultCount = expectedResult?.nodes ? expectedResult.nodes.length : 0;
      diff = `Expected count: ${expectedResultCount} vs actual count: ${resultNodes.length}`;
      Logger.info(`${TAB}${diff}`);
    } else {
      diff = expectedAndActualMatch(expectedResult.nodes, resultNodes);
    }

    if (diff) {
      Logger.info(`${TAB}Test failed. Expected and actual results differ.`);
    }
  } catch (error) {
    Logger.info(`${TAB}Test failed. ` + error);
  }

  return diff;
}

function runTest(testDir: string, testFile: string, mode: Mode): boolean {
  if (mode === Mode.AUTOFIX && fs.existsSync(path.join(testDir, testFile + AUTOFIX_SKIP_EXT))) {
    Logger.info(`Skipping test ${testFile} (${Mode[mode]} mode)`);
    return false;
  }
  Logger.info(`Running test ${testFile} (${Mode[mode]} mode)`);

  TypeScriptLinter.initGlobals();
  InteropTypescriptLinter.initGlobals();

  const currentTestMode = TypeScriptLinter.testMode;
  const currentInteropTestMode = InteropTypescriptLinter.testMode;
  const cmdOptions = parseArgs(testDir, testFile, mode);
  const lintOptions = compileLintOptions(cmdOptions, enableCheckTsFile);
  lintOptions.compatibleSdkVersion = '12';
  lintOptions.compatibleSdkVersionStage = 'beta3';
  const result = lint(lintOptions, getEtsLoaderPath(lintOptions));
  const fileProblems = result.problemsInfos.get(path.normalize(cmdOptions.inputFiles[0]));
  if (fileProblems === undefined) {
    return true;
  }

  TypeScriptLinter.testMode = currentTestMode;
  InteropTypescriptLinter.testMode = currentInteropTestMode;

  // Get list of bad nodes from the current run.
  const resultNodes = getResultNodesByRunLinter(fileProblems, mode);

  // Read file with expected test result.
  const testResult = compareExpectedAndActual(testDir, testFile, mode, resultNodes);

  // Write file with actual test results.
  writeActualResultFile(testDir, testFile, mode, resultNodes, testResult);

  return !!testResult;
}

function getResultNodesByRunLinter(fileProblems: ProblemInfo[], mode: Mode): TestNodeInfo[] {
  return fileProblems.map<TestNodeInfo>((x) => {
    return {
      line: x.line,
      column: x.column,
      endLine: x.endLine,
      endColumn: x.endColumn,
      problem: x.problem,
      autofix: mode === Mode.AUTOFIX ? x.autofix : undefined,
      suggest: x.suggest,
      rule: x.rule,
      severity: ProblemSeverity[x.severity]
    };
  });
}

function expectedAndActualMatch(expectedNodes: TestNodeInfo[], actualNodes: TestNodeInfo[]): string {
  // Compare expected and actual results.
  for (let i = 0; i < actualNodes.length; i++) {
    const actual = actualNodes[i];
    const expect = expectedNodes[i];
    if (!locationMatch(expect, actual) || actual.problem !== expect.problem) {
      return reportDiff(expect, actual);
    }
    if (!autofixArraysMatch(expect.autofix, actual.autofix)) {
      return reportDiff(expect, actual);
    }
    if (expect.suggest && actual.suggest !== expect.suggest) {
      return reportDiff(expect, actual);
    }
    if (expect.rule && actual.rule !== expect.rule) {
      return reportDiff(expect, actual);
    }
    if (expect.severity && actual.severity !== expect.severity) {
      return reportDiff(expect, actual);
    }
  }

  return '';
}

function locationMatch(expected: TestNodeInfo, actual: TestNodeInfo): boolean {
  return (
    actual.line === expected.line &&
    actual.column === expected.column &&
    (!expected.endLine || actual.endLine === expected.endLine) &&
    (!expected.endColumn || actual.endColumn === expected.endColumn)
  );
}

function autofixArraysMatch(expected: Autofix[] | undefined, actual: Autofix[] | undefined): boolean {
  if (!expected && !actual) {
    return true;
  }
  if (!(expected && actual) || expected.length !== actual.length) {
    return false;
  }
  for (let i = 0; i < actual.length; ++i) {
    if (
      actual[i].start !== expected[i].start ||
      actual[i].end !== expected[i].end ||
      actual[i].replacementText !== expected[i].replacementText
    ) {
      return false;
    }
  }
  return true;
}

function writeActualResultFile(
  testDir: string,
  testFile: string,
  mode: Mode,
  resultNodes: TestNodeInfo[],
  diff: string
): void {
  const actualResultsDir = path.join(testDir, enableUseRtLogic ? 'results_rt' : 'results_sdk');
  const resultExt = RESULT_EXT[mode];
  if (!fs.existsSync(actualResultsDir)) {
    fs.mkdirSync(actualResultsDir);
  }

  const actualResultJSON = JSON.stringify({ nodes: resultNodes }, null, 4);
  fs.writeFileSync(path.join(actualResultsDir, testFile + resultExt), actualResultJSON);

  if (diff) {
    fs.writeFileSync(path.join(actualResultsDir, testFile + resultExt + DIFF_EXT), diff);
  }
}

function reportDiff(expected: TestNodeInfo, actual: TestNodeInfo): string {
  const expectedNode = JSON.stringify({ nodes: [expected] }, null, 4);
  const actualNode = JSON.stringify({ nodes: [actual] }, null, 4);

  const diff = `Expected:
${expectedNode}
Actual:
${actualNode}`;

  Logger.info(diff);
  return diff;
}

runTests();
