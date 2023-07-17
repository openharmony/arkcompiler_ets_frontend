const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const testDirectory = path.resolve('./test/local');

function runTest(filePath) {
  try {
    const command = `node ./node_modules/ts-node/dist/bin.js ${filePath}`;
    execSync(command);
    return true;
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
    } else if (path.extname(filePath) === '.ts') {
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