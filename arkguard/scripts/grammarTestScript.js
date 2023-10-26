/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const testDirectory = path.resolve('./test/local');

function compareWithExpected(filePath) {
  const expectedFilePath = filePath.replace(/\.ts$/, '-expected.txt');

  if (!fs.existsSync(expectedFilePath)) {
    return true;
  }

  const actualContent = fs.readFileSync(filePath, 'utf-8').trim();
  const expectedContent = fs.readFileSync(expectedFilePath, 'utf-8').trim();

  return actualContent === expectedContent;
}

function runTest(filePath) {
  try {
    const command = `node ./node_modules/ts-node/dist/bin.js ${filePath}`;
    execSync(command);
    if (compareWithExpected(filePath)) {
      return true;
    } else {
      console.error(`Test case ${filePath} failed: Content does not match`);
      return false;
    }
  } catch (error) {
    console.error(`Test case ${filePath} failed:`, error);
    return false;
  }
}
let successCount = 0;
let failureCount = 0;
const failedFiles = [];

function runTestsInDirectory(directoryPath) {
  const files = fs.readdirSync(directoryPath);

  for (const file of files) {
    const filePath = path.join(directoryPath, file);

    if (fs.statSync(filePath).isDirectory()) {
      runTestsInDirectory(filePath);
    } else if (filePath.includes('obfuscation_validation')) {
      if (filePath.includes('assert.ts')) {
        const isSuccess = runTest(filePath);
        if (isSuccess) {
          successCount++;
        } else {
          failureCount++;
          failedFiles.push(filePath);
        }
      }
    } else if (path.extname(filePath) === '.ts' || path.extname(filePath) === '.js') {
      const isSuccess = runTest(filePath);
      if (isSuccess) {
        successCount++;
      } else {
        failureCount++;
        failedFiles.push(filePath);
      }
    }
  }
}

runTestsInDirectory(testDirectory);

console.log('--- Grammar Test Results ---');
console.log(`Success count: ${successCount}`);
console.log(`Failure count: ${failureCount}`);
if (failureCount > 0) {
  console.log('Failed files:');
  for (const failedFile of failedFiles) {
    console.log(failedFile);
  }
}