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

import {factory, SyntaxKind} from 'typescript';
import type {BinaryExpression, Block, Expression, IfStatement, Statement} from 'typescript';
import crypto from 'crypto';

import {AbstractBogusControlHelper} from './AbstractBogusControlHelper';
import {NodeUtils} from '../../utils/NodeUtils';
import type {INameGenerator} from '../../generator/INameGenerator';

export class SimpleBogusControlHelper extends AbstractBogusControlHelper {
  protected mNameGenerator: INameGenerator;

  public constructor(units: Statement[], useOpaquePredicate: boolean, nameGenerator: INameGenerator) {
    super(units, useOpaquePredicate);
    this.mNameGenerator = nameGenerator;
  }

  public getNewBlock(bogusBlock: Block): Block {
    const preStatements: Statement[] = [];
    const randomMaxValue: number = 100;
    const useTrue: boolean = (crypto.randomInt(randomMaxValue) & 1) === 0;

    let predicate: Expression;
    if (this.mUseOpaquePredicate) {
      predicate = this.createOpaquePredicate(preStatements, useTrue);
    } else {
      predicate = this.createSimplePredicate(preStatements, useTrue);
    }

    const originalBlock: Block = factory.createBlock([...this.mOriginalUnits], true);

    let ifStatement: IfStatement;
    if (useTrue) {
      ifStatement = factory.createIfStatement(predicate, originalBlock, bogusBlock);
    } else {
      ifStatement = factory.createIfStatement(predicate, bogusBlock, originalBlock);
    }

    return factory.createBlock(
      [
        ...preStatements,
        ifStatement
      ],
      true
    );
  }

  public createSimplePredicate(preStatements: Statement[], useTrue: boolean): Expression {
    const arrayName: string = this.mNameGenerator.getName();
    const stringArray: string[] = [];
    const traversalRange: number = 10;
    for (let i = 0; i < traversalRange; i++) {
      stringArray.push(this.mNameGenerator.getName());
    }

    const arrayInitStatement: Statement = NodeUtils.createArrayInit(true, arrayName,
      SyntaxKind.StringLiteral, stringArray);
    preStatements.push(arrayInitStatement);

    const syntaxSymbol: SyntaxKind = useTrue ? SyntaxKind.ExclamationEqualsEqualsToken :
      SyntaxKind.EqualsEqualsEqualsToken;

    return factory.createBinaryExpression(
      factory.createElementAccessExpression(
        factory.createIdentifier(arrayName),
        factory.createNumericLiteral('1')
      ),
      syntaxSymbol,
      factory.createElementAccessExpression(
        factory.createIdentifier(arrayName),
        factory.createNumericLiteral('6')
      )
    );
  }

  /**
   * create condition judgement use opaque predicate
   */
  public createOpaquePredicate(preStatements, useTrue: boolean): Expression {
    const nameGenerator: INameGenerator = this.mNameGenerator;

    const xName: string = nameGenerator.getName();
    const randomMaxValue: number = 125;
    preStatements.push(NodeUtils.createNumericWithRandom(xName, 1, randomMaxValue));

    /**
     * y < 10 || x * (x + 1) % 2 == 0, always true
     * x is integer
     */
    function method1(): BinaryExpression {
      const yName: string = nameGenerator.getName();
      preStatements.push(NodeUtils.createNumericWithRandom(yName, 1, randomMaxValue));

      const left: BinaryExpression = factory.createBinaryExpression(
        factory.createIdentifier(yName),
        SyntaxKind.LessThanToken,
        factory.createNumericLiteral('10')
      );

      const rightLeft: BinaryExpression = factory.createBinaryExpression(
        factory.createBinaryExpression(
          factory.createIdentifier(xName),
          SyntaxKind.AsteriskToken,
          factory.createParenthesizedExpression(
            factory.createBinaryExpression(
              factory.createIdentifier(xName),
              SyntaxKind.PlusToken,
              factory.createNumericLiteral('1')
            )
          )
        ),
        SyntaxKind.PercentToken,
        factory.createNumericLiteral('2')
      );

      const right: BinaryExpression = factory.createBinaryExpression(
        rightLeft,
        SyntaxKind.EqualsEqualsEqualsToken,
        factory.createNumericLiteral('0')
      );

      return factory.createBinaryExpression(
        left,
        SyntaxKind.BarBarToken,
        right
      );
    }

    /**
     * 7* x* x − y* y != 1 || y < n, always true
     * x, y in [0, 125);
     * n in [0, 125];
     */
    function method2(): BinaryExpression {
      const yName: string = nameGenerator.getName();
      const randomMaxValue: number = 125;
      preStatements.push(NodeUtils.createNumericWithRandom(yName, 1, randomMaxValue));

      const nName: string = nameGenerator.getName();
      preStatements.push(NodeUtils.createNumericWithRandom(nName, 0, randomMaxValue));

      const left: BinaryExpression = factory.createBinaryExpression(
        factory.createBinaryExpression(
          factory.createBinaryExpression(
            factory.createBinaryExpression(
              factory.createNumericLiteral('7'),
              SyntaxKind.AsteriskToken,
              factory.createIdentifier(xName)
            ),
            SyntaxKind.AsteriskToken,
            factory.createIdentifier(xName)
          ),
          SyntaxKind.MinusToken,
          factory.createBinaryExpression(
            factory.createIdentifier(yName),
            SyntaxKind.AsteriskToken,
            factory.createIdentifier(yName)
          )
        ),
        SyntaxKind.ExclamationEqualsEqualsToken,
        factory.createNumericLiteral('1')
      );

      const right: BinaryExpression = factory.createBinaryExpression(
        factory.createIdentifier(yName),
        SyntaxKind.LessThanToken,
        factory.createIdentifier(nName)
      );

      return factory.createBinaryExpression(
        left,
        SyntaxKind.BarBarToken,
        right
      );
    }

    /**
     * (4*x*x + 1) % 19 != 0, always true
     */
    function method3(): BinaryExpression {
      const leftInner: BinaryExpression = factory.createBinaryExpression(
        factory.createBinaryExpression(
          factory.createBinaryExpression(
            factory.createNumericLiteral('4'),
            SyntaxKind.AsteriskToken,
            factory.createIdentifier(xName)
          ),
          SyntaxKind.AsteriskToken,
          factory.createIdentifier(xName)
        ),
        SyntaxKind.PlusToken,
        factory.createNumericLiteral('4')
      );

      const left: BinaryExpression = factory.createBinaryExpression(
        factory.createParenthesizedExpression(
          leftInner
        ),
        SyntaxKind.PercentToken,
        factory.createNumericLiteral('19')
      );

      return factory.createBinaryExpression(
        left,
        SyntaxKind.ExclamationEqualsEqualsToken,
        factory.createNumericLiteral('0')
      );
    }

    /**
     * (x*x + x +7) % 81 != 0, always true
     */
    function method4(): BinaryExpression {
      const leftInner: BinaryExpression = factory.createBinaryExpression(
        factory.createBinaryExpression(
          factory.createBinaryExpression(
            factory.createIdentifier(xName),
            SyntaxKind.AsteriskToken,
            factory.createIdentifier(xName)
          ),
          SyntaxKind.PlusToken,
          factory.createIdentifier(xName)
        ),
        SyntaxKind.PlusToken,
        factory.createNumericLiteral('7')
      );

      const left: BinaryExpression = factory.createBinaryExpression(
        factory.createParenthesizedExpression(
          leftInner
        ),
        SyntaxKind.PercentToken,
        factory.createNumericLiteral('81')
      );

      return factory.createBinaryExpression(
        left,
        SyntaxKind.ExclamationEqualsEqualsToken,
        factory.createNumericLiteral('0')
      );
    }

    /**
     * (x*x*x -x) % 3 == 0, always true
     */
    function method5(): BinaryExpression {
      const leftInner: BinaryExpression = factory.createBinaryExpression(
        factory.createBinaryExpression(
          factory.createBinaryExpression(
            factory.createIdentifier(xName),
            SyntaxKind.AsteriskToken,
            factory.createIdentifier(xName)
          ),
          SyntaxKind.AsteriskToken,
          factory.createIdentifier(xName)
        ),
        SyntaxKind.MinusToken,
        factory.createIdentifier(xName)
      );

      const left: BinaryExpression = factory.createBinaryExpression(
        factory.createParenthesizedExpression(
          leftInner
        ),
        SyntaxKind.PercentToken,
        factory.createNumericLiteral('3')
      );

      return factory.createBinaryExpression(
        left,
        SyntaxKind.EqualsEqualsEqualsToken,
        factory.createNumericLiteral('0')
      );
    }

    const methodList: (() => BinaryExpression)[] = [method1, method2, method3, method4, method5];
    const opaqueMethod: () => BinaryExpression = methodList[crypto.randomInt(methodList.length)];

    if (useTrue) {
      return opaqueMethod();
    }

    return factory.createPrefixUnaryExpression(
      SyntaxKind.ExclamationToken,
      factory.createParenthesizedExpression(
        opaqueMethod()
      )
    );
  }
}
