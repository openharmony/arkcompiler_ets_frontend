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
import { faultsAttrs } from '../FaultAttrs';
import { FaultID } from '../Problems';

const BACKUP_AFFIX = '~';
const EOL = '\n';
export const MAX_AUTOFIX_PASSES = 10;
const DEPENDENT_RULES_IN_AUTOFIX: Set<number> = new Set([faultsAttrs[FaultID.ObjectLiteralNoContextType].cookBookRef]);

export class QuasiEditor {
  private textBuffer;
  private readonly dataBuffer;
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
    for (const str of srcLines) {
      fs.appendFileSync(this.srcFileName, str + EOL);
    }
  }

  private replaceAt(start: number, len: number, newText: string): void {
    const head = this.textBuffer.slice(0, start);
    const tail = this.textBuffer.slice(start + len);
    this.textBuffer = head + newText + tail;
  }

  applyFixes(problemInfos: ProblemInfo[]): void {
    let lastFixStart = this.textBuffer.length;
    if (problemInfos.length === 0) {
      return;
    }
    for (let i = problemInfos.length - 1; i >= 0; i--) {
      const pInfo = problemInfos[i];
      if (!pInfo.autofix) {
        continue;
      }
      for (let j = pInfo.autofix.length - 1; j >= 0; j--) {
        if (pInfo.autofix[j].end >= lastFixStart || pInfo.autofix[j].start >= lastFixStart) {
          Logger.error(`Error: ${this.srcFileName} (${lastFixStart}) fix intersectection ${pInfo.autofixTitle}`);
          this.wasError = true;
          continue;
        }
        if (DEPENDENT_RULES_IN_AUTOFIX.has(pInfo.ruleTag)) {
          Logger.error(`Error: ${this.srcFileName} (${lastFixStart}) fix has dependent rule ${pInfo.autofixTitle}`);
          this.wasError = true;
          continue;
        }
        this.replaceAt(
          lastFixStart = pInfo.autofix[j].start,
          pInfo.autofix[j].end - pInfo.autofix[j].start,
          pInfo.autofix[j].replacementText
        );
      }
    }
    this.saveText();
  }

  private static autofixesIntersect(lhs: Autofix, rhs: Autofix): boolean {
    return !(lhs.end < rhs.start || rhs.end < lhs.start);
  }
}
