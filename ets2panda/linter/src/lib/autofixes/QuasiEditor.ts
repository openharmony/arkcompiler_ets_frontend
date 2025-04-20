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
import { Logger } from '../Logger';
import type * as ts from 'typescript';
import type { ProblemInfo } from '../ProblemInfo';
import type { Autofix } from './Autofixer';

const BACKUP_AFFIX = '~';
const EOL = '\n';
export const MAX_AUTOFIX_PASSES = 10;

export class QuasiEditor {
  private textBuffer: string;
  private readonly dataBuffer: Buffer;
  private readonly srcFileName: string;
  wasError: boolean = false;

  constructor(
    readonly sourceFile: ts.SourceFile,
    readonly passNumber?: number,
    readonly cancellationToken?: ts.CancellationToken
  ) {
    this.srcFileName = this.sourceFile.fileName;

    /*
     * need to backup only once "this.backupSrcFile();"
     * load text into buffer
     */
    this.dataBuffer = fs.readFileSync(this.srcFileName);
    this.textBuffer = this.dataBuffer.toString();
    if (!passNumber) {
      passNumber = 1;
    }
  }

  backupSrcFile(): void {
    fs.copyFileSync(this.srcFileName, this.srcFileName + BACKUP_AFFIX);
  }

  backupSrcFileDebug(pass: number): void {
    fs.copyFileSync(this.srcFileName, this.srcFileName + BACKUP_AFFIX + pass.toString());
  }

  private saveText(): void {
    fs.truncateSync(this.srcFileName);

    const srcLines = this.textBuffer.split(EOL);
    for (let i = 0; i < srcLines.length - 1; i++) {
      fs.appendFileSync(this.srcFileName, srcLines[i] + EOL);
    }
    // check if last line is empty out of loop to optimize
    if (srcLines[srcLines.length - 1] !== '') {
      fs.appendFileSync(this.srcFileName, srcLines[srcLines.length - 1] + EOL);
    }
  }

  private static hasAnyAutofixes(problemInfos: ProblemInfo[]): boolean {
    return problemInfos.some((problemInfo) => {
      return problemInfo.autofix !== undefined;
    });
  }

  private generateReport(acceptedPatches: Autofix[]): void {
    const report = {
      filePath: this.srcFileName,
      fixCount: acceptedPatches.length,
      fixes: acceptedPatches.map((fix) => {
        return {
          start: fix.start,
          end: fix.end,
          replacement: fix.replacementText,
          original: this.dataBuffer.toString().slice(fix.start, fix.end)
        };
      }),
    };

    const reportPath = './autofix-report.html';

    try {
      fs.writeFileSync(reportPath, JSON.stringify(report, null, 2), { encoding: 'utf-8' });
    } catch (error) {
      Logger.error(`failed to create autofix reoprt: ${(error as Error).message}`);
      this.wasError = true;
    }
  }

  fix(problemInfos: ProblemInfo[]): void {
    if (!QuasiEditor.hasAnyAutofixes(problemInfos)) {
      return;
    }
    const acceptedPatches = QuasiEditor.sortAndRemoveIntersections(problemInfos);
    this.textBuffer = this.applyFixes(acceptedPatches);
    this.saveText();
    this.generateReport(acceptedPatches);
  }

  private applyFixes(autofixes: Autofix[]): string {
    let output: string = '';
    let lastPos = Number.NEGATIVE_INFINITY;

    const doFix = (fix: Autofix): void => {
      const { replacementText, start, end } = fix;

      if (lastPos >= start || start > end) {
        Logger.error(`Failed to apply autofix in range [${start}, ${end}] at ${this.srcFileName}`);
        return;
      }

      output += this.textBuffer.slice(Math.max(0, lastPos), Math.max(0, start));
      output += replacementText;
      lastPos = end;
    };

    autofixes.forEach(doFix);
    output += this.textBuffer.slice(Math.max(0, lastPos));

    return output;
  }

  private static sortAndRemoveIntersections(problemInfos: ProblemInfo[]): Autofix[] {
    let acceptedPatches: Autofix[] = [];

    problemInfos.forEach((problemInfo) => {
      if (!problemInfo.autofix) {
        return;
      }

      const consideredAutofix = QuasiEditor.sortAutofixes(problemInfo.autofix);
      if (QuasiEditor.intersect(consideredAutofix, acceptedPatches)) {
        return;
      }

      acceptedPatches.push(...consideredAutofix);
      acceptedPatches = QuasiEditor.sortAutofixes(acceptedPatches);
    });

    return acceptedPatches;
  }

  private static sortAutofixes(autofixes: Autofix[]): Autofix[] {
    return autofixes.sort((a, b) => {
      return a.start - b.start;
    });
  }

  /**
   * Determine if considered autofix can be accepted.
   *
   * @param consideredAutofix sorted patches of the considered autofix
   * @param acceptedFixes sorted list of accepted autofixes
   * @returns
   */
  private static intersect(consideredAutofix: readonly Autofix[], acceptedFixes: readonly Autofix[]): boolean {
    const start = consideredAutofix[0].start;
    const end = consideredAutofix[consideredAutofix.length - 1].end;

    for (const acceptedFix of acceptedFixes) {
      if (acceptedFix.start > end) {
        break;
      }

      if (acceptedFix.end < start) {
        continue;
      }

      for (const consideredFix of consideredAutofix) {
        if (QuasiEditor.autofixesIntersect(acceptedFix, consideredFix)) {
          return true;
        }
      }
    }
    return false;
  }

  private static autofixesIntersect(lhs: Autofix, rhs: Autofix): boolean {

    /*
     * Ranges don't intersect if either
     * [--]         (lhs)
     *      [--]    (rhs)
     * or
     *      [--]    (lhs)
     * [--]         (rhs)
     */
    return !(lhs.end < rhs.start || rhs.end < lhs.start);
  }
}
