/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
import type { LinterConfig } from '../lib/LinterConfig';
import { Logger } from '../lib/Logger';
import { compileLintOptions } from '../lib/ts-compiler/Compiler';
import type { LintRunResult } from '../lib/LintRunResult';
import { DIFF_EXT, MIGRATE_RESULT_SUFFIX, RESULTS_DIR, TAB } from './Consts';
import { LintTest } from './LintTest';
import type { CreateLintTestOptions } from './TestFactory';
import { readLines } from './FileUtil';

export class MigrateTest extends LintTest {
  constructor(createLintTestOpts: CreateLintTestOptions) {
    super(createLintTestOpts);
  }

  compile(): LinterConfig {
    this.cmdOptions.linterOptions.migratorMode = true;

    // Set filepath mapping to write migration result at 'results' dir instead of modifying original test file
    const filePathMap = new Map();
    filePathMap.set(
      path.normalize(path.join(this.testDir, this.testFile)),
      path.normalize(this.getActualMigrateResultsFilePath())
    );
    this.cmdOptions.linterOptions.migrationFilePathMap = filePathMap;

    return compileLintOptions(this.cmdOptions);
  }

  validate(actualLinterResult: LintRunResult): boolean {
    const validateBase = super.validate(actualLinterResult);
    const validateMigrateResult = this.validateMigrateResult();
    return validateBase && validateMigrateResult;
  }

  private validateMigrateResult(): boolean {
    this.writeMigrationResultForUnchangedFiles();
    const resultDiff = this.compareMigrateResult();
    if (resultDiff) {
      this.writeMigrateDiff(resultDiff);
    }
    return !resultDiff;
  }

  private compareMigrateResult(): string {
    let diff: string = '';
    try {
      const expectedResult = readFileLines(this.getExpectedMigrateResultsFilePath());
      const actualResult = readFileLines(this.getActualMigrateResultsFilePath());

      if (expectedResult.length !== actualResult.length) {
        diff = `Expected lines: ${expectedResult.length} vs actual lines: ${actualResult.length}`;
      } else {
        diff = MigrateTest.compareTextLines(expectedResult, actualResult);
      }

      if (diff) {
        Logger.info(`${TAB}Migration test failed. Expected and actual results differ:\n${diff}`);
      }
    } catch (error) {
      // Write error message to diff, as non-empty diff indicates that test has failed.
      diff = (error as Error).message;
      Logger.info(`${TAB}Failed to compare expected and actual results. ` + diff);
    }

    return diff;
  }

  private static compareTextLines(expected: string[], actual: string[]): string {
    for (let i = 0; i < expected.length && i < actual.length; i++) {
      if (expected[i] !== actual[i]) {
        const diff = `Difference at line ${i + 1} 
Expected:
${expected[i]}
Actual:
${actual[i]}`;
        return diff;
      }
    }
    return '';
  }

  writeMigrateDiff(diff: string): void {
    fs.writeFileSync(this.getActualMigrateResultsFilePath() + DIFF_EXT, diff);
  }

  writeMigrationResultForUnchangedFiles(): void {

    /*
     * If test file doesn't produce any autofix, the migration result won't be created.
     * In such case, use original text of the test file as migration result.
     */
    const filePathMap = this.cmdOptions.linterOptions.migrationFilePathMap;
    if (!filePathMap) {
      return;
    }
    filePathMap.forEach((targetFile, srcFile) => {
      if (fs.existsSync(targetFile)) {
        return;
      }
      fs.copyFileSync(srcFile, targetFile);
    });
  }

  private getMigrateResultFileName(): string {
    return this.testFile + MIGRATE_RESULT_SUFFIX + path.extname(this.testFile);
  }

  private getExpectedMigrateResultsFilePath(): string {
    return path.join(this.testDir, this.getMigrateResultFileName());
  }

  private getActualMigrateResultsFilePath(): string {
    return path.join(this.testDir, RESULTS_DIR, this.getMigrateResultFileName());
  }
}

function readFileLines(filePath: string): string[] {
  try {
    return readLines(filePath);
  } catch (error) {
    throw new Error(`Failed to process ${filePath}: ${(error as Error).message}`);
  }
}
