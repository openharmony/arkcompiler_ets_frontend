/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import {
  factory,
  isIdentifierStart,
  isReturnStatement,
  ScriptTarget,
  SyntaxKind,
  NodeFlags
} from 'typescript';

import type {
  CaseClause,
  ObjectLiteralExpression,
  PropertyAssignment,
  Statement,
  SwitchStatement,
  CallExpression,
  VariableStatement,
  ElementAccessExpression
} from 'typescript';

import {randomInt} from 'crypto';

import {table as confusionTable} from '../../configs/preset/ConfusionTables';
import {SimpleControlFlowFlattenHelper} from './SimpleControlFlowFlattenHelper';

export class ConfusedCharsFlattenHelper extends SimpleControlFlowFlattenHelper {
  private readonly mChoiceName: string;

  private mMangledTable: Map<number, string[]>;

  private mChooseMaps: Map<number, string>;

  public constructor(units: Statement[], reservedNames: Set<string>) {
    super(units, reservedNames);

    this.mChoiceName = this.mNameGenerator.getName();
    reservedNames.add(this.mChoiceName);

    this.mMangledTable = new Map<number, string[]>();
    this.mChooseMaps = new Map<number, string>();

    let index: number = 0;
    const confusionTableKeys: string[] = Object.keys(confusionTable);
    for (const key of confusionTableKeys) {
      this.mMangledTable.set(index++, confusionTable[key]);
    }

    index = 0;
    let chooseList: string[] = this.chooseMangledChars();
    for (const [key, _] of this.mStatementUnits) {
      this.mChooseMaps.set(key, chooseList[index++]);
    }
  }

  private chooseMangledChars(): string[] {
    let chooseList: Set<string> = new Set<string>();
    let remainLen: number = this.mOriginalUnits.length;
    let historyIndex: Set<number> = new Set<number>();

    while (remainLen > 0) {
      if (historyIndex.size === this.mMangledTable.size) {
        const MIN_UNICODE = 0x100;
        const MAX_UNICODE = 0x7fff;
        let unicode: number = randomInt(MIN_UNICODE, MAX_UNICODE);
        if (isIdentifierStart(unicode, ScriptTarget.ES2015)) {
          chooseList.add(String.fromCharCode(unicode));
          remainLen = this.mOriginalUnits.length - chooseList.size;
        }

        continue;
      }

      let choice: number = randomInt(0, this.mMangledTable.size);
      if (historyIndex.has(choice)) {
        continue;
      }

      historyIndex.add(choice);
      let chars: string[] = this.mMangledTable.get(choice).filter((ch) => {
        return isIdentifierStart(ch.codePointAt(0), ScriptTarget.ES2015);
      });

      let len: number = chars.length > remainLen ? remainLen : chars.length;
      chars.slice(0, len).forEach((ch) => {
        chooseList.add(ch);
      });

      remainLen = this.mOriginalUnits.length - chooseList.size;
    }

    return Array.from(chooseList);
  }

  public getVariableRelatedStatements(): Statement[] {
    let properties: PropertyAssignment[] = [];
    this.mChooseMaps.forEach((val, _) => {
      const RANDOM_MIN = 0;
      const RANDOM_MAX = 36;
      const propValue = randomInt(RANDOM_MIN, RANDOM_MAX);
      let prop: PropertyAssignment = factory.createPropertyAssignment(val, factory.createNumericLiteral(propValue));
      properties.push(prop);
    });

    let literal: ObjectLiteralExpression = factory.createObjectLiteralExpression(properties);

    const choiceExpression: CallExpression = factory.createCallExpression(
      factory.createPropertyAccessExpression(
        factory.createIdentifier('Object'),
        factory.createIdentifier('keys')
      ),
      undefined,
      [factory.createIdentifier(this.mOrderObjName)]
    );

    const variableStatement: VariableStatement = factory.createVariableStatement(
      undefined,
      factory.createVariableDeclarationList(
        [
          factory.createVariableDeclaration(this.mOrderObjName, undefined, undefined, literal),
          factory.createVariableDeclaration(this.mIndexName, undefined, undefined, factory.createNumericLiteral(0)),
          factory.createVariableDeclaration(this.mChoiceName, undefined, undefined, choiceExpression)
        ],
        NodeFlags.Let
      )
    );

    return [variableStatement];
  }

  public getSwitchStruct(): SwitchStatement {
    let condition: ElementAccessExpression = factory.createElementAccessExpression(
      factory.createIdentifier(this.mChoiceName),
      factory.createPostfixUnaryExpression(factory.createIdentifier(this.mIndexName), SyntaxKind.PlusPlusToken)
    );

    let caseList: CaseClause[] = [];
    for (let index = 0; index < this.mOriginalUnits.length; index++) {
      let st: Statement = this.mStatementUnits.get(index);
      let statements: Statement[] = isReturnStatement(st) ? [st] : [st, factory.createContinueStatement()];
      let caseSt: CaseClause = factory.createCaseClause(
        factory.createStringLiteral(this.mChooseMaps.get(index)), statements);
      caseList.push(caseSt);
    }

    return factory.createSwitchStatement(condition, factory.createCaseBlock(caseList));
  }
}
