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

import type * as ts from 'typescript';
import type { LinterOptions } from './LinterOptions';
import type { ProblemInfo } from './ProblemInfo';
import type { Autofix } from './autofixes/Autofixer';
import { FileStatistics } from './statistics/FileStatistics';
import { TsUtils } from './utils/TsUtils';
import { cookBookRefToFixTitle } from './autofixes/AutofixTitles';
import { faultDesc } from './FaultDesc';
import { TypeScriptLinterConfig } from './TypeScriptLinterConfig';
import { faultsAttrs } from './FaultAttrs';
import { cookBookTag } from './CookBookMsg';
import { FaultID } from './Problems';
import { ProblemSeverity } from './ProblemSeverity';
import { arkts2Rules, onlyArkts2SyntaxRules } from './utils/consts/ArkTS2Rules';

export abstract class BaseTypeScriptLinter {
  problemsInfos: ProblemInfo[] = [];
  fileStats: FileStatistics;
  tsUtils: TsUtils;

  constructor(
    protected readonly tsTypeChecker: ts.TypeChecker,
    readonly options: LinterOptions,
    protected sourceFile: ts.SourceFile
  ) {
    this.tsUtils = new TsUtils(this.tsTypeChecker, options);
    this.fileStats = new FileStatistics(sourceFile, this.problemsInfos);
  }

  protected getLineAndCharacterOfNode(node: ts.Node | ts.CommentRange): ts.LineAndCharacter {
    const startPos = TsUtils.getStartPos(node);
    const { line, character } = this.sourceFile.getLineAndCharacterOfPosition(startPos);
    // TSC counts lines and columns from zero
    return { line: line + 1, character: character + 1 };
  }

  abstract lint(): void;

  protected updateFileStats(faultId: number, line: number): void {
    this.fileStats.nodeCounters[faultId]++;
    this.fileStats.lineCounters[faultId].add(line);
  }

  protected static addLineColumnInfoInAutofix(
    autofix: Autofix[],
    startPos: ts.LineAndCharacter,
    endPos: ts.LineAndCharacter
  ): Autofix[] {
    return autofix?.map((autofixElem) => {
      autofixElem.line = startPos.line + 1;
      autofixElem.column = startPos.character + 1;
      autofixElem.endLine = endPos.line + 1;
      autofixElem.endColumn = endPos.character + 1;
      return autofixElem;
    });
  }

  protected incrementCounters(
    node: ts.Node | ts.CommentRange,
    faultId: number,
    autofix?: Autofix[],
    errorMsg?: string
  ): void {
    const badNodeInfo = this.getbadNodeInfo(node, faultId, autofix, errorMsg);

    if (this.shouldSkipRule(badNodeInfo)) {
      return;
    }

    this.problemsInfos.push(badNodeInfo);
    this.updateFileStats(faultId, badNodeInfo.line);
    // problems with autofixes might be collected separately
    if (this.options.reportAutofixCb && badNodeInfo.autofix) {
      this.options.reportAutofixCb(badNodeInfo);
    }
  }

  private getbadNodeInfo(
    node: ts.Node | ts.CommentRange,
    faultId: number,
    autofix?: Autofix[],
    errorMsg?: string
  ): ProblemInfo {
    const [startOffset, endOffset] = TsUtils.getHighlightRange(node, faultId);
    const startPos = this.sourceFile.getLineAndCharacterOfPosition(startOffset);
    const endPos = this.sourceFile.getLineAndCharacterOfPosition(endOffset);
    const faultDescr = faultDesc[faultId];
    const faultType = TypeScriptLinterConfig.tsSyntaxKindNames[node.kind];
    const cookBookMsgNum = faultsAttrs[faultId] ? faultsAttrs[faultId].cookBookRef : 0;
    const cookBookTg = errorMsg ? errorMsg : cookBookTag[cookBookMsgNum];
    const severity = faultsAttrs[faultId]?.severity ?? ProblemSeverity.ERROR;
    const isMsgNumValid = cookBookMsgNum > 0;
    autofix = BaseTypeScriptLinter.processAutofix(autofix, startPos, endPos);
    const badNodeInfo: ProblemInfo = {
      line: startPos.line + 1,
      column: startPos.character + 1,
      endLine: endPos.line + 1,
      endColumn: endPos.character + 1,
      start: startOffset,
      end: endOffset,
      type: faultType,
      severity: severity,
      faultId: faultId,
      problem: FaultID[faultId],
      suggest: '',
      // eslint-disable-next-line no-nested-ternary
      rule: isMsgNumValid && cookBookTg !== '' ? cookBookTg : faultDescr ? faultDescr : faultType,
      ruleTag: cookBookMsgNum,
      autofixable: !!autofix,
      autofix: autofix,
      autofixTitle: isMsgNumValid && autofix !== undefined ? cookBookRefToFixTitle.get(cookBookMsgNum) : undefined
    };
    return badNodeInfo;
  }

  private static processAutofix(
    autofix: Autofix[] | undefined,
    startPos: ts.LineAndCharacter,
    endPos: ts.LineAndCharacter
  ): Autofix[] | undefined {
    return autofix ? BaseTypeScriptLinter.addLineColumnInfoInAutofix(autofix, startPos, endPos) : autofix;
  }

  private shouldSkipRule(badNodeInfo: ProblemInfo): boolean {
    const ruleConfigTags = this.options.ruleConfigTags;
    if (ruleConfigTags && !ruleConfigTags.has(badNodeInfo.ruleTag)) {
      return true;
    }
    if (this.options?.ideInteractive) {
      if (this.options.onlySyntax) {
        if (onlyArkts2SyntaxRules.has(badNodeInfo.ruleTag)) {
          return false;
        }
      } else if (this.options.arkts2 && arkts2Rules.includes(badNodeInfo.ruleTag)) {
        return false;
      }
      return true;
    }
    return false;
  }
}
