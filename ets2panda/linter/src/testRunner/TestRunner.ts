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
import { LoggerImpl } from '../cli/LoggerImpl';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as ts from 'typescript';
import type { CommandLineOptions } from '../lib/CommandLineOptions';
import { lint } from '../lib/LinterRunner';
import { TypeScriptLinter } from '../lib/TypeScriptLinter';
import { InteropTypescriptLinter } from '../lib/InteropTypescriptLinter';
import type { Autofix } from '../lib/autofixes/Autofixer';
import { parseCommandLine as parseLinterCommandLine } from '../cli/CommandLineParser';
import { compileLintOptions } from '../cli/Compiler';
import { getEtsLoaderPath } from '../cli/LinterCLI';
import { ProblemSeverity } from '../lib/ProblemSeverity';
import type { ProblemInfo } from '../lib/ProblemInfo';
import type { TestArguments } from './TestArgs';
import { validateTestArgs } from './TestArgs';
import type { LinterOptions } from '../lib/LinterOptions';
import { Command } from 'commander';
import { rimrafSync } from 'rimraf';
import type { TestProblemInfo, TestResult } from './TestResult';
import { validateTestResult } from './TestResult';
import { globSync } from 'glob';
import type { Path } from 'path-scurry';
import { PathScurry } from 'path-scurry';
import { getCommandLineArguments } from './CommandLineUtil';

Logger.init(new LoggerImpl());

const TAB = '    ';
const RESULTS_DIR = 'results';

const ARGS_CONFIG_EXT = '.args.json';
const DIFF_EXT = '.diff';
const TEST_EXTENSION_STS = '.sts';
const TEST_EXTENSION_STSX = '.stsx';
const TEST_EXTENSION_D_STS = '.d.sts';

interface TestStatistics {
  passed: number;
  failed: number;
}

enum TestMode {
  DEFAULT,
  AUTOFIX,
  ARKTS2
}

interface CreateTestConfigurationOptions {
  runTestFileOpts: RunTestFileOptions;
  testModeProps: TestModeProperties;
  testModeArgs?: string;
  testCommonOpts?: LinterOptions;
}

interface TestRunnerOptions {
  linterOptions: LinterOptions;
  testDirs: string[];
  testPattern?: string;
}

interface RunTestFileOptions {
  testDir: string;
  testFile: string;
  testRunnerOpts: TestRunnerOptions;
}

interface TestModeProperties {
  resultFileExt: string;
  mode: TestMode;
  modeOpts: LinterOptions /* Options that enable specific mode */;
}

const DEFAULT_MODE_PROPERTIES: TestModeProperties = {
  resultFileExt: '.json',
  mode: TestMode.DEFAULT,
  modeOpts: {}
};
const AUTOFIX_MODE_PROPERTIES: TestModeProperties = {
  resultFileExt: '.autofix.json',
  mode: TestMode.AUTOFIX,
  modeOpts: {
    enableAutofix: true
  }
};
const ARKTS2_MODE_PROPERTIES: TestModeProperties = {
  resultFileExt: '.arkts2.json',
  mode: TestMode.ARKTS2,
  modeOpts: {
    arkts2: true
  }
};

interface TestConfiguration {
  testDir: string;
  testFile: string;
  testModeProps: TestModeProperties;
  cmdOptions: CommandLineOptions;
}

export function getSdkConfigOptions(configFile: string): ts.CompilerOptions {
  // initial configuration
  const options = ts.readConfigFile(configFile, ts.sys.readFile).config.compilerOptions;

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

  return options;
}

function parseCommandLine(commandLineArgs: string[]): TestRunnerOptions {
  const program = new Command();
  program.
    name('testrunner').
    description('Test Runner for Linter tests').
    configureHelp({ helpWidth: 100 }).
    version('1.0.0');
  program.
    requiredOption(
      '-d, --test-dir <test_dir>',
      'Specifies a directory with test files. Multiple directories can be specified with a comma-separated list'
    ).
    option(
      '-p, --test-pattern <pattern>',
      'Specifies a glob pattern to filter the list of tests. The path from the pattern is resolved to test directory. ' +
        'Note: Only tests in specified test directory will be run, and the sub-directories will be ignored.'
    ).
    option('--sdk', 'Use SDK check logic').
    option('--interop-mode', 'Run interop-mode check');

  // method parse() eats two first args, so make them dummy
  const cmdArgs: string[] = ['dummy', 'dummy'];
  cmdArgs.push(...commandLineArgs);
  program.parse(cmdArgs);
  const programOpts = program.opts();
  const testRunnerOpts: TestRunnerOptions = {
    testDirs: processTestDirArg(programOpts.testDir),
    linterOptions: {}
  };
  if (programOpts.testPattern) {
    testRunnerOpts.testPattern = programOpts.testPattern;
  }
  if (programOpts.interopMode) {
    testRunnerOpts.linterOptions.interopCheckMode = true;
  }
  if (programOpts.sdk) {
    testRunnerOpts.linterOptions.useRtLogic = false;
  }
  return testRunnerOpts;
}

function processTestDirArg(testDirs: string | undefined): string[] {
  if (!testDirs) {
    return [];
  }
  return testDirs.
    split(',').
    map((val) => {
      return val.trim();
    }).
    filter((val) => {
      return val.length > 0;
    });
}

function runTests(): boolean {
  const testRunnerOpts = parseCommandLine(process.argv.slice(2));
  const testStats: TestStatistics = { passed: 0, failed: 0 };
  // Get tests from test directory
  for (const testDir of testRunnerOpts.testDirs) {
    if (!fs.existsSync(testDir)) {
      Logger.info(`\nThe "${testDir}" directory doesn't exist.\n`);
      continue;
    }
    Logger.info(`\nProcessing "${testDir}" directory:\n`);
    rimrafSync(path.join(testDir, RESULTS_DIR));
    let testFiles: string[] = testRunnerOpts.testPattern ?
      collectTestFilesWithGlob(testDir, testRunnerOpts.testPattern) :
      fs.readdirSync(testDir);
    testFiles = testFiles.filter((x) => {
      return (
        x.trimEnd().endsWith(ts.Extension.Ts) && !x.trimEnd().endsWith(ts.Extension.Dts) ||
        x.trimEnd().endsWith(ts.Extension.Tsx) ||
        x.trimEnd().endsWith(ts.Extension.Ets) ||
        x.trimEnd().endsWith(TEST_EXTENSION_STS) && !x.trimEnd().endsWith(TEST_EXTENSION_D_STS) ||
        x.trimEnd().endsWith(TEST_EXTENSION_STSX)
      );
    });
    runTestFiles(testFiles, testDir, testRunnerOpts, testStats);
  }
  const { passed, failed } = testStats;
  Logger.info(`\nSUMMARY: ${passed + failed} total, ${passed} passed, ${failed} failed.`);
  Logger.info(failed > 0 ? '\nTEST FAILED' : '\nTEST SUCCESSFUL');
  process.exit(failed > 0 ? -1 : 0);
}

function collectTestFilesWithGlob(testDir: string, pattern: string): string[] {
  const testDirPath = new PathScurry(testDir).cwd.fullpath();
  return globSync(pattern, {
    cwd: testDir,
    ignore: {
      childrenIgnored(p: Path): boolean {
        return p.fullpath() !== testDirPath;
      }
    }
  }).sort();
}

function runTestFiles(
  testFiles: string[],
  testDir: string,
  testRunnerOpts: TestRunnerOptions,
  testStats: TestStatistics
): void {
  for (const testFile of testFiles) {
    try {
      let renamed = false;
      let tsName = testFile;
      if (testFile.includes(TEST_EXTENSION_STS)) {
        renamed = true;
        tsName = testFile.replace(TEST_EXTENSION_STS, ts.Extension.Ts);
        fs.renameSync(path.join(testDir, testFile), path.join(testDir, tsName));
      }
      runTestFile({ testDir, testFile: tsName, testRunnerOpts }, testStats);
      if (renamed) {
        fs.renameSync(path.join(testDir, tsName), path.join(testDir, testFile));
      }
    } catch (error) {
      Logger.info(`Test ${testFile} failed:\n${TAB}` + (error as Error).message);
      testStats.failed++;
    }
  }
}

function runTestFile(runTestFileOpts: RunTestFileOptions, testStats: TestStatistics): void {
  const testConfigs: TestConfiguration[] = [];

  const testArgs = processTestArgsFile(runTestFileOpts.testDir, runTestFileOpts.testFile);
  if (testArgs) {
    const testCommonOpts = testArgs.commonArgs ? getLinterOptionsFromCommandLine(testArgs.commonArgs) : undefined;
    addTestConfiguration(testConfigs, {
      runTestFileOpts,
      testModeProps: DEFAULT_MODE_PROPERTIES,
      testModeArgs: testArgs.mode?.default,
      testCommonOpts
    });
    addTestConfiguration(testConfigs, {
      runTestFileOpts,
      testModeProps: AUTOFIX_MODE_PROPERTIES,
      testModeArgs: testArgs.mode?.autofix,
      testCommonOpts
    });
    addTestConfiguration(testConfigs, {
      runTestFileOpts,
      testModeProps: ARKTS2_MODE_PROPERTIES,
      testModeArgs: testArgs.mode?.arkts2,
      testCommonOpts
    });
  } else {
    addTestConfiguration(testConfigs, { runTestFileOpts, testModeProps: DEFAULT_MODE_PROPERTIES });
  }

  testConfigs.forEach((config: TestConfiguration) => {
    if (runTest(config)) {
      ++testStats.passed;
    } else {
      ++testStats.failed;
    }
  });
}

function processTestArgsFile(testDir: string, testFile: string): TestArguments | undefined {
  const argsFileName = path.join(testDir, testFile + ARGS_CONFIG_EXT);
  if (fs.existsSync(argsFileName)) {
    try {
      const data = fs.readFileSync(argsFileName).toString();
      const json = JSON.parse(data);
      return validateTestArgs(json);
    } catch (error) {
      throw new Error(`Failed to process ${argsFileName}: ${(error as Error).message}`);
    }
  }
  return undefined;
}

function addTestConfiguration(
  testConfigs: TestConfiguration[],
  createTestConfigOpts: CreateTestConfigurationOptions
): void {
  const { runTestFileOpts, testModeProps, testModeArgs, testCommonOpts } = createTestConfigOpts;
  const { testDir, testFile, testRunnerOpts } = runTestFileOpts;

  if (testModeArgs === undefined && testModeProps.mode !== TestMode.DEFAULT) {
    return;
  }

  /*
   * Test options are formed in the following order (from lowest to highest priority):
   *   - default test options;
   *   - [test_args_file] --> 'commonArgs';
   *   - [test_args_file] --> the arguments specified for a mode;
   *   - options specified by TestRunner command-line arguments;
   *   - options that enable specific mode.
   */
  const linterOpts = getDefaultTestOptions();
  if (testCommonOpts) {
    Object.assign(linterOpts, testCommonOpts);
  }
  if (testModeArgs) {
    Object.assign(linterOpts, getLinterOptionsFromCommandLine(testModeArgs));
  }
  Object.assign(linterOpts, testRunnerOpts.linterOptions);
  Object.assign(linterOpts, testModeProps.modeOpts);

  const cmdOptions: CommandLineOptions = {
    inputFiles: [path.join(testDir, testFile)],
    linterOptions: linterOpts
  };

  testConfigs.push({
    testDir,
    testFile,
    testModeProps,
    cmdOptions
  });
}

function getDefaultTestOptions(): LinterOptions {

  /*
   * Set the IDE mode manually to enable storing information
   * about found bad nodes and also disable the log output.
   */
  return {
    ideMode: true,
    useRtLogic: true,
    checkTsAsSource: true /* Currently, tests have '.ts' extension, therefore, enable this flag by default */,
    compatibleSdkVersion: 12,
    compatibleSdkVersionStage: 'beta3'
  };
}

function getLinterOptionsFromCommandLine(cmdLine: string): LinterOptions {
  return parseLinterCommandLine(getCommandLineArguments(cmdLine), { exitOnFail: false, disableErrorOutput: true }).
    linterOptions;
}

function runTest(testConfig: TestConfiguration): boolean {
  Logger.info(`Running test ${testConfig.testFile} (${TestMode[testConfig.testModeProps.mode]} mode)`);

  TypeScriptLinter.initGlobals();
  InteropTypescriptLinter.initGlobals();

  const linterConfig = compileLintOptions(testConfig.cmdOptions);
  const linterResult = lint(linterConfig, getEtsLoaderPath(linterConfig));

  // Get actual test results.
  const fileProblems = linterResult.problemsInfos.get(path.normalize(testConfig.cmdOptions.inputFiles[0]));
  if (fileProblems === undefined) {
    return true;
  }
  const actualResult = transformProblemInfos(fileProblems, testConfig.testModeProps.mode);

  // Read file with expected test result.
  const resultDiff = compareExpectedAndActual(testConfig, actualResult);

  // Write file with actual test results.
  writeActualResultFile(testConfig, actualResult, resultDiff);

  return !resultDiff;
}

function readTestResultFile(testDir: string, testResultFileName: string): TestProblemInfo[] {
  const filePath = path.join(testDir, testResultFileName);
  try {
    const testResult = fs.readFileSync(filePath).toString();
    return validateTestResult(JSON.parse(testResult)).result;
  } catch (error) {
    throw new Error(`Failed to process ${filePath}: ${(error as Error).message}`);
  }
}

function transformProblemInfos(fileProblems: ProblemInfo[], mode: TestMode): TestProblemInfo[] {
  return fileProblems.map<TestProblemInfo>((x) => {
    return {
      line: x.line,
      column: x.column,
      endLine: x.endLine,
      endColumn: x.endColumn,
      problem: x.problem,
      autofix: mode === TestMode.AUTOFIX ? x.autofix : undefined,
      suggest: x.suggest,
      rule: x.rule,
      severity: ProblemSeverity[x.severity]
    };
  });
}

function compareExpectedAndActual(testConfig: TestConfiguration, actual: TestProblemInfo[]): string {
  const {
    testDir,
    testFile,
    cmdOptions: { linterOptions },
    testModeProps: { resultFileExt }
  } = testConfig;

  // Read file with expected test result.
  let diff: string = '';
  const testResultFileName = testFile + resultFileExt;
  try {
    let expected = readTestResultFile(testDir, testResultFileName);

    /**
     * The exclusive field is added to identify whether the use case is exclusive to the RT or SDK
     * RT means the RT exclusive
     * SDK means the SDK exclusive
     * undefined means shared
     */
    expected = expected.filter((x) => {
      return !x?.exclusive || x.exclusive === (linterOptions.useRtLogic ? 'RT' : 'SDK');
    });

    if (!expected || expected.length !== actual.length) {
      const expectedResultCount = expected ? expected.length : 0;
      diff = `Expected count: ${expectedResultCount} vs actual count: ${actual.length}`;
      Logger.info(`${TAB}${diff}`);
    } else {
      diff = expectedAndActualMatch(expected, actual);
    }

    if (diff) {
      Logger.info(`${TAB}Test failed. Expected and actual results differ.`);
    }
  } catch (error) {
    // Write error message to diff, as non-empty diff indicates that test has failed.
    diff = (error as Error).message;
    Logger.info(`${TAB}Failed to compare expected and actual results. ` + diff);
  }

  return diff;
}

function expectedAndActualMatch(expectedNodes: TestProblemInfo[], actualNodes: TestProblemInfo[]): string {
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

function locationMatch(expected: TestProblemInfo, actual: TestProblemInfo): boolean {
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

function writeActualResultFile(testConfig: TestConfiguration, actual: TestProblemInfo[], diff: string): void {
  const {
    testModeProps: { resultFileExt }
  } = testConfig;
  const actualResultsDir = path.join(testConfig.testDir, RESULTS_DIR);
  if (!fs.existsSync(actualResultsDir)) {
    fs.mkdirSync(actualResultsDir);
  }

  const actualTestResult: TestResult = { result: actual };
  const actualResultJSON = JSON.stringify(actualTestResult, null, 4);
  fs.writeFileSync(path.join(actualResultsDir, testConfig.testFile + resultFileExt), actualResultJSON);

  if (diff) {
    fs.writeFileSync(path.join(actualResultsDir, testConfig.testFile + resultFileExt + DIFF_EXT), diff);
  }
}

function reportDiff(expected: TestProblemInfo, actual: TestProblemInfo): string {
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
