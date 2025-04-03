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

import path from 'path';
import fs from 'fs';
import {
  Lsp,
  LspDefinitionData,
  LspCompletionInfo,
  LspDiagsNode,
  ModuleDescriptor,
  generateArkTsConfigByModules
} from '../src/index';

interface TestConfig {
  expectedFilePath: string;
  // CC-OFFNXT(no_explicit_any) project code style
  [key: string]: Array<any> | string;
}

interface TestCases {
  [testName: string]: TestConfig;
}

let updateMode = false;

function checkEnvironment(testDir: string): void {
  const testCasesFilePath = path.join(testDir, 'testcases', 'cases.json');
  if (!fs.existsSync(testCasesFilePath)) {
    console.error(`Test cases file not found: ${testCasesFilePath}`);
    process.exit(1);
  }
}

function getModules(projectRoot: string): ModuleDescriptor[] {
  const testCases = JSON.parse(fs.readFileSync(path.join(projectRoot, 'cases.json'), 'utf-8')) as TestCases;
  return Object.keys(testCases).map((name) => {
    const modulePath = path.join(projectRoot, name);
    return {
      arktsversion: '1.2',
      name,
      moduleType: 'har',
      srcPath: modulePath
    } as ModuleDescriptor;
  });
}

// CC-OFFNXT(no_explicit_any) project code style
function getExpectedResult(filePath: string): any {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
  } catch (err) {
    console.error(`Failed to read expected result from ${filePath}: ${err}`);
    return null;
  }
}

function sortCompletions(completionResult: LspCompletionInfo): LspCompletionInfo {
  if (!completionResult || !completionResult.entries || !Array.isArray(completionResult.entries)) {
    return completionResult;
  }

  // Sort entries by name
  completionResult.entries.sort((a, b) => {
    const nameA = a.name.toString().toLowerCase();
    const nameB = b.name.toString().toLowerCase();
    return nameA.localeCompare(nameB);
  });

  return completionResult;
}

function sortDiagnostics(diags: LspDiagsNode): LspDiagsNode {
  if (!diags || !diags.diagnostics || !Array.isArray(diags.diagnostics)) {
    return diags;
  }

  diags.diagnostics.sort((a, b) => {
    if (a.range.start.line !== b.range.start.line) {
      return a.range.start.line - b.range.start.line;
    }

    if (a.range.start.character !== b.range.start.character) {
      return a.range.start.character - b.range.start.character;
    }

    if (a.range.end.line !== b.range.end.line) {
      return a.range.end.line - b.range.end.line;
    }

    return a.range.end.character - b.range.end.character;
  });

  return diags;
}

// CC-OFFNXT(no_explicit_any) project code style
function sortActualResult(testName: string, res: any): any {
  if (testName === 'getCompletionAtPosition') {
    return sortCompletions(res as LspCompletionInfo);
  }
  if (testName === 'getSuggestionDiagnostics') {
    return sortDiagnostics(res as LspDiagsNode);
  }
  return res;
}

// CC-OFFNXT(no_explicit_any) project code style
function normalizeData(obj: any): any {
  if (Array.isArray(obj)) {
    return obj.map(normalizeData);
  } else if (obj && typeof obj === 'object') {
    const newObj = { ...obj };
    if ('peer' in newObj) {
      delete newObj.peer; // do not compare peer
    }
    if (newObj.fileName) {
      newObj.fileName = path.basename(newObj.fileName);
    }
    for (const key of Object.keys(newObj)) {
      newObj[key] = normalizeData(newObj[key]);
    }
    return newObj;
  }
  return obj;
}

// CC-OFFNXT(no_explicit_any) project code style
function compareResultsHelper(testName: string, actual: any, expected: any): boolean {
  const normalizedActual = normalizeData(actual);

  const actualJSON = JSON.stringify(normalizedActual, null, 2);
  const expectedJSON = JSON.stringify(expected, null, 2);

  if (actualJSON === expectedJSON) {
    console.log(`[${testName}] ✅ Passed`);
    return true;
  } else {
    console.log(`[${testName}] ❌ Failed`);
    console.log(`Expected: ${expectedJSON}`);
    console.log(`Actual:   ${actualJSON}`);
  }
  return false;
}

function findTextDefinitionPosition(sourceCode: string): number {
  const textDefinitionPattern = /export\s+declare\s+function\s+Text\(/;
  const match = textDefinitionPattern.exec(sourceCode);
  if (match) {
    const functionTextPattern = /function\s+Text\(/;
    const subMatch = functionTextPattern.exec(sourceCode.substring(match.index));
    if (subMatch) {
      const positionOfT = match.index + subMatch.index + 'function '.length;
      return positionOfT;
    }
  }
  throw new Error('Could not find Text definition in source code');
}

function compareGetDefinitionResult(
  testName: string,
  index: string,
  actual: any,
  expected: Record<string, string | number>
) {
  // This is the definition info for the UI component.
  // File in the SDK might changed, so the offset needs to be checked dynamically.
  if (expected['fileName'] === 'text.d.ets') {
    const actualDef = actual as LspDefinitionData;
    const fileName = actualDef.fileName as string;
    const fileContent = fs.readFileSync(fileName, 'utf8');
    const expectedStart = findTextDefinitionPosition(fileContent);
    const expectedResult = {
      ...expected,
      start: expectedStart
    };
    return compareResultsHelper(`${testName}:${index}`, actual, expectedResult);
  }
  return compareResultsHelper(`${testName}:${index}`, actual, expected);
}

// CC-OFFNXT(no_explicit_any) project code style
function compareResults(testName: string, index: string, actual: any, expected: any) {
  if (testName === 'getDefinitionAtPosition') {
    return compareGetDefinitionResult(testName, index, actual, expected);
  }
  return compareResultsHelper(`${testName}:${index}`, actual, expected);
}

function runTests(testDir: string, lsp: Lsp) {
  console.log('Running tests...');
  const testCases = JSON.parse(fs.readFileSync(path.join(testDir, 'testcases', 'cases.json'), 'utf-8')) as TestCases;
  if (!testCases) {
    console.error('Failed to load test cases');
    return;
  }

  let failedList: string[] = [];
  for (const [testName, testConfig] of Object.entries(testCases)) {
    const { expectedFilePath, ...testCaseVariants } = testConfig;
    const expectedResult = getExpectedResult(expectedFilePath);
    if (expectedResult === null) {
      console.error(`[${testName}] Skipped (expected result not found)`);
      continue;
    }
    // CC-OFFNXT(no_explicit_any) project code style
    if (typeof (lsp as any)[testName] !== 'function') {
      console.error(`[${testName}] ❌ Error: Method "${testName}" not found on Lsp object`);
      continue;
    }

    for (const [index, params] of Object.entries(testCaseVariants)) {
      let pass = false;
      let actualResult = null;
      try {
        // CC-OFFNXT(no_explicit_any) project code style
        actualResult = (lsp as any)[testName](...params);
        actualResult = sortActualResult(testName, actualResult);
        pass = compareResults(testName, index, actualResult, expectedResult[index]);
      } catch (error) {
        console.error(`[${testName}:${index}] ❌ Error: ${error}`);
      }
      if (!pass) {
        failedList.push(`${testName}:${index}`);
      }
      if (!pass && updateMode) {
        console.log(`Updating expected result for ${testName}:${index}`);
        expectedResult[index] = normalizeData(actualResult);
      }
    }
    if (updateMode) {
      fs.writeFileSync(expectedFilePath, JSON.stringify(expectedResult, null, 2));
    }
    console.log(`Finished test: ${testName}`);
    console.log('-----------------------------------');
  }
  console.log('Tests completed.');
  if (failedList.length > 0) {
    console.log('❌ Failed tests:');
    failedList.forEach((failedCase) => {
      console.log(`- ${failedCase}`);
    });
  }
}

if (require.main === module) {
  if (process.argv.length < 3) {
    console.error('Usage: node run_tests.js <test_directory>');
    process.exit(1);
  }
  // If update flag is passed, update the expected result files
  if (process.argv[3] && process.argv[3] === '--update') {
    updateMode = true;
  }
  const testDir = path.resolve(process.argv[2]);
  checkEnvironment(testDir);
  const buildSdkPath = path.join(testDir, 'ets', 'ets1.2');
  const projectRoot = path.join(testDir, 'testcases');
  const modules = getModules(projectRoot);

  generateArkTsConfigByModules(buildSdkPath, projectRoot, modules);
  const lsp = new Lsp(projectRoot);

  process.env.BINDINGS_PATH = path.join(buildSdkPath, 'build-tools', 'bindings');
  runTests(testDir, lsp);
}
