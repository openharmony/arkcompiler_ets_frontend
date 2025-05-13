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
import type * as ts from 'typescript';
import { Logger } from '../Logger';
import type { ProblemInfo } from '../ProblemInfo';
import type { Autofix } from './Autofixer';
import type { LinterOptions } from '../LinterOptions';
import { AUTOFIX_HTML_TEMPLATE_TEXT, AutofixHtmlTemplate } from './AutofixReportHtmlHelper';

const BACKUP_AFFIX = '~';
export const DEFAULT_MAX_AUTOFIX_PASSES = 10;

export class QuasiEditor {
  constructor(
    readonly srcFileName: string,
    readonly sourceText: string,
    readonly linterOpts: LinterOptions,
    readonly cancellationToken?: ts.CancellationToken
  ) {}

  private static getBackupFileName(filePath: string): string {
    return filePath + BACKUP_AFFIX;
  }

  static backupSrcFile(filePath: string): void {
    fs.copyFileSync(filePath, QuasiEditor.getBackupFileName(filePath));
  }

  static hasAnyAutofixes(problemInfos: ProblemInfo[]): boolean {
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
          line: fix.line,
          colum: fix.column,
          endLine: fix.endLine,
          endColum: fix.endColumn,
          start: fix.start,
          end: fix.end,
          replacement: fix.replacementText,
          original: this.sourceText.slice(fix.start, fix.end)
        };
      })
    };

    const reportPath = './autofix-report.html';
    const getOldJsonArray = (reportPath: string): Set<any> => {
      try {
        const RegexCaptureBraketFirst = 1;
        const rawData = fs.readFileSync(reportPath, 'utf-8');
        const rawContent = rawData.match(/`([\s\S]*?)`/)?.[RegexCaptureBraketFirst] ?? '';
        return new Set(JSON.parse(rawContent) || []);
      } catch {
        return new Set();
      }
    };

    try {
      const existingReports = getOldJsonArray(reportPath);
      existingReports.add(report);
      const str = JSON.stringify([...existingReports], null, 2);
      const HtmlContent = AutofixHtmlTemplate.replace(AUTOFIX_HTML_TEMPLATE_TEXT, str);
      fs.writeFileSync(reportPath, HtmlContent, { encoding: 'utf-8' });
    } catch (error) {
      Logger.error(`Failed to update autofix report: ${(error as Error).message}`);
    }
  }

  fix(problemInfos: ProblemInfo[]): string {
    const acceptedPatches = QuasiEditor.sortAndRemoveIntersections(problemInfos);
    const result = this.applyFixes(acceptedPatches);

    if (this.linterOpts.migrationReport) {
      this.generateReport(acceptedPatches);
    }

    return result;
  }

  private applyFixes(autofixes: Autofix[]): string {
    let output: string = '';
    let lastFixEnd = Number.NEGATIVE_INFINITY;

    const doFix = (fix: Autofix): void => {
      const { replacementText, start, end } = fix;

      if (lastFixEnd > start || start > end) {
        Logger.error(`Failed to apply autofix in range [${start}, ${end}] at ${this.srcFileName}`);
        return;
      }

      output += this.sourceText.slice(Math.max(0, lastFixEnd), Math.max(0, start));
      output += replacementText;
      lastFixEnd = end;
    };

    autofixes.forEach(doFix);
    output += this.sourceText.slice(Math.max(0, lastFixEnd));

    return output;
  }

  private static sortAndRemoveIntersections(problemInfos: ProblemInfo[]): Autofix[] {
    let acceptedPatches: Autofix[] = [];

    problemInfos.forEach((problemInfo): void => {
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
    return autofixes.sort((a, b): number => {
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
