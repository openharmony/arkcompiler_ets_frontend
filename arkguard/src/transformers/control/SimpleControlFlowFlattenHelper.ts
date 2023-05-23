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

import {
  factory,
  isReturnStatement,
  Map,
  NodeFlags,
  SyntaxKind,
} from 'typescript';

import type {
  Block,
  CaseClause,
  ElementAccessExpression,
  Expression,
  ForStatement,
  NumericLiteral,
  Statement,
  SwitchStatement,
  WhileStatement
} from 'typescript';

import crypto from 'crypto';

import {AbstractControlFlowFlattenHelper} from './AbstractControlFlowFlattenHelper';
import {ListUtil} from '../../utils/ListUtil';

export class SimpleControlFlowFlattenHelper extends AbstractControlFlowFlattenHelper {
  protected mIndexArrayName: string;
  protected mStringArray: number[];
  protected mIndexArray: number[];

  public constructor(units: Statement[], reservedNames: Set<string>) {
    super(units, reservedNames);

    this.mIndexArrayName = this.mNameGenerator.getName();
    reservedNames.add(this.mIndexArrayName);

    let shuffledArr: number[] = ListUtil.getInitList(units.length);
    ListUtil.shuffle(shuffledArr);

    this.mStringArray = [...shuffledArr];
    ListUtil.shuffle(this.mStringArray);

    this.mIndexArray = [];
    shuffledArr.forEach((value) => {
      this.mIndexArray.push(this.mStringArray.indexOf(value));
    });

    this.mStatementUnits = new Map<number, Statement>();
    let index: number = 0;
    shuffledArr.forEach((val) => {
      this.mStatementUnits.set(val, this.mOriginalUnits[index++]);
    });
  }

  public getSwitchStruct(): SwitchStatement {
    let condition: ElementAccessExpression = factory.createElementAccessExpression(
      factory.createIdentifier(this.mOrderObjName),
      factory.createElementAccessExpression(
        factory.createIdentifier(this.mIndexArrayName),
        factory.createPostfixUnaryExpression(
          factory.createIdentifier(this.mIndexName),
          SyntaxKind.PlusPlusToken
        )
      ));

    let caseList: CaseClause[] = [];
    for (let index = 0; index < this.mOriginalUnits.length; index++) {
      let st: Statement = this.mStatementUnits.get(index);
      let statements: Statement[] = isReturnStatement(st) ? [st] : [st, factory.createContinueStatement()];
      let caseSt: CaseClause = factory.createCaseClause(
        factory.createStringLiteral(index.toString()), statements);
      caseList.push(caseSt);
    }

    return factory.createSwitchStatement(condition, factory.createCaseBlock(caseList));
  }

  public getLoopStruct(): WhileStatement | ForStatement {
    let loopBody: Block = factory.createBlock([
      this.getSwitchStruct(),
      factory.createBreakStatement(),
    ]);

    const MAX_RANDOM = 100;
    const HALF_RANDOM = 100;
    const temp: number = crypto.randomInt(MAX_RANDOM);
    let choice: boolean = temp > HALF_RANDOM;
    if (choice) {
      return factory.createForStatement(undefined, undefined, undefined, loopBody);
    }

    let condition: Expression = this.getLoopCondition();
    return factory.createWhileStatement(condition, loopBody);
  }

  public getLoopCondition(): Expression {
    return factory.createPrefixUnaryExpression(
      SyntaxKind.ExclamationToken,
      factory.createPrefixUnaryExpression(
        SyntaxKind.ExclamationToken,
        factory.createArrayLiteralExpression([])
      )
    );
  }

  public getVariableRelatedStatements(): Statement[] {
    let indexStr: string = this.mStringArray.join('|');

    let arrayList: NumericLiteral[] = [];
    this.mIndexArray.forEach((value) => {
      arrayList.push(factory.createNumericLiteral(value.toString()));
    });

    return [
      factory.createVariableStatement(
        undefined,
        factory.createVariableDeclarationList(
          [
            factory.createVariableDeclaration(
              factory.createIdentifier(this.mOrderObjName),
              undefined,
              undefined,
              factory.createCallExpression(
                factory.createPropertyAccessExpression(
                  factory.createStringLiteral(indexStr),
                  factory.createIdentifier('split')
                ),
                undefined,
                [factory.createStringLiteral('|')]
              )
            ),
            factory.createVariableDeclaration(
              factory.createIdentifier(this.mIndexArrayName),
              undefined,
              undefined,
              factory.createArrayLiteralExpression(arrayList)
            ),
            factory.createVariableDeclaration(
              factory.createIdentifier(this.mIndexName),
              undefined,
              undefined,
              factory.createNumericLiteral(0)
            )
          ],
          NodeFlags.Let
        )
      )
    ];
  }
}
