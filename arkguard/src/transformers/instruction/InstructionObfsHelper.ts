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
  NodeFlags,
  SyntaxKind,
} from 'typescript';

import type {
  BinaryExpression, 
  Block, 
  CallExpression, 
  Expression, 
  FunctionExpression,
  Identifier, 
  ObjectLiteralExpression,
  ParameterDeclaration, 
  ParenthesizedExpression, 
  PropertyAssignment,
  VariableStatement
} from 'typescript';

import * as crypto from 'crypto';
import type {INameGenerator} from '../../generator/INameGenerator';
import {NodeUtils} from '../../utils/NodeUtils';

export class InstructionHelper {
  private readonly mArgcFuncMap: Map<number, string>;
  private readonly mReservedIdentifiers: Set<string>;
  private readonly mNameGenerator: INameGenerator;

  constructor(nameGenerator: INameGenerator) {
    this.mArgcFuncMap = new Map<number, string>();
    this.mReservedIdentifiers = new Set<string>();
    this.mNameGenerator = nameGenerator;
  }

  /**
   * ignore deform for special function call
   * @param callExpression
   * @private
   */
  private isSpecialFunctionCall(callExpression: CallExpression): boolean {
    return callExpression.expression.kind === SyntaxKind.SuperKeyword;
  }

  /**
   * deform call expression, only support function of identifier expression
   * @param callExpression
   * @param varName
   * @param pairArray
   */
  public deformCallExpression(callExpression: CallExpression, varName: string, pairArray: PropertyAssignment[]): CallExpression {
    if (this.isSpecialFunctionCall(callExpression)) {
      return callExpression;
    }

    // parse the information in the original instruction: function name, parameter list, and number of parameters
    const argsCount: number = callExpression.arguments.length;

    for (const arg of callExpression.arguments) {
      if (arg.kind === SyntaxKind.Identifier) {
        this.mReservedIdentifiers.add((arg as Identifier).text);
      }
    }

    const funcName: Expression = {...callExpression.expression};

    // if there is no deformation function corresponding to the number of parameters, 
    // generate a new pair, add it to the pairArray, and update the argcMap
    if (this.mArgcFuncMap.get(argsCount) === undefined) {
      const newPair: PropertyAssignment = this.createPair(argsCount);
      pairArray.push(newPair);
    }

    // query the corresponding deformation function name in argcMap and deform callExpression
    return factory.createCallExpression(
      factory.createElementAccessExpression(
        factory.createIdentifier(varName),
        factory.createStringLiteral(this.mArgcFuncMap.get(argsCount))
      ),
      undefined,
      [
        funcName,
        ...callExpression.arguments
      ]
    );
  }

  public getReservedIdentifiers(): Set<string> {
    return this.mReservedIdentifiers;
  }

  public createPair(argsCount: number): PropertyAssignment {
    const key: string = this.mNameGenerator.getName();
    this.mArgcFuncMap.set(argsCount, key);

    return factory.createPropertyAssignment(
      factory.createStringLiteral(key),
      this.createFunc(argsCount)
    );
  }

  private createFunc(argsCount: number): FunctionExpression {
    let parametersList: ParameterDeclaration[] = [];
    let parameterNameList: string[] = [];

    // 1. create function parameter
    for (let i = 0; i < argsCount + 1; i++) {
      const parameterName: string = this.mNameGenerator.getName();
      parameterNameList.push(parameterName);

      const funcParameter: ParameterDeclaration = factory.createParameterDeclaration(
        undefined,
        undefined,
        undefined,
        factory.createIdentifier(parameterName)
      );
      parametersList.push(funcParameter);
    }

    // 2. create call expression parameter
    const callParametersList: Identifier[] = [];
    for (let i = 1; i < argsCount + 1; i++) {
      callParametersList.push(factory.createIdentifier(parameterNameList[i]));
    }

    // 3. create function body
    const funcBlock: Block = factory.createBlock(
      [
        factory.createReturnStatement(
          factory.createCallExpression(
            factory.createIdentifier(parameterNameList[0]),
            undefined,
            callParametersList
          )
        )
      ],
      true
    );

    return factory.createFunctionExpression(
      undefined,
      undefined,
      undefined,
      undefined,
      parametersList,
      undefined,
      funcBlock
    );
  }

  public createCallMapStatement(varName: string, pairArray: PropertyAssignment[]): VariableStatement {
    const value: ObjectLiteralExpression = this.createCallMapValue(pairArray);

    return factory.createVariableStatement(
      undefined,
      factory.createVariableDeclarationList(
        [
          factory.createVariableDeclaration(
            factory.createIdentifier(varName),
            undefined,
            undefined,
            value
          )
        ],
        NodeFlags.Const
      )
    );
  }

  private createCallMapValue(pairArray: PropertyAssignment[]): ObjectLiteralExpression {
    return factory.createObjectLiteralExpression(
      pairArray,
      true
    );
  }

  public obfuscateBinaryExpression(binaryExpression: BinaryExpression): Expression {
    switch (binaryExpression.operatorToken.kind) {
      case SyntaxKind.MinusToken:
        return this.createMinusMBA(binaryExpression);
      case SyntaxKind.CaretToken:
        // a^b
        return this.createCaretMBA(binaryExpression);
      case SyntaxKind.BarToken:
        // a|b
        return this.createBarMBA(binaryExpression);
      case SyntaxKind.AmpersandToken:
        // a&b
        return this.createAmpersandMBA(binaryExpression);
      default:
        return binaryExpression;
    }
  }

  private createMinusMBA(minusExpression: BinaryExpression): BinaryExpression {
    /**
     * decimal part: x - y + Math.truc(y) - Math.trunc(x)
     */
    function getDecimalMinus(): BinaryExpression {
      return factory.createBinaryExpression(
        factory.createBinaryExpression(
          factory.createBinaryExpression(
            {...minusExpression.left},
            SyntaxKind.MinusToken,
            {...minusExpression.right}
          ),
          SyntaxKind.PlusToken,
          NodeUtils.createTruncExpression(minusExpression.right)
        ),
        SyntaxKind.MinusToken,
        NodeUtils.createTruncExpression(minusExpression.left)
      );
    }

    /**
     * get minus expression of higher 32 bit
     * trunc(x) - (x|0) - trunc(y) + (y|0)
     */
    function getHigh32Minus(): BinaryExpression {
      return factory.createBinaryExpression(
        factory.createBinaryExpression(
          factory.createBinaryExpression(
            NodeUtils.createTruncExpression(minusExpression.left),
            SyntaxKind.MinusToken,
            NodeUtils.createLowerExpression(minusExpression.left)
          ),
          SyntaxKind.MinusToken,
          NodeUtils.createTruncExpression(minusExpression.right)
        ),
        SyntaxKind.PlusToken,
        NodeUtils.createLowerExpression(minusExpression.right)
      );
    }

    /**
     * x - y = (x|0) + ((y^-1) + 1), for lower 32 bit
     */
    function method1(): BinaryExpression {
      const right: ParenthesizedExpression = factory.createParenthesizedExpression(
        factory.createBinaryExpression(
          factory.createParenthesizedExpression(
            factory.createBinaryExpression(
              {...minusExpression.right},
              SyntaxKind.CaretToken,
              factory.createPrefixUnaryExpression(
                SyntaxKind.MinusToken,
                factory.createNumericLiteral('1')
              )
            )
          ),
          SyntaxKind.PlusToken,
          factory.createNumericLiteral('1')
        )
      );

      return factory.createBinaryExpression(
        NodeUtils.createLowerExpression(minusExpression.left),
        SyntaxKind.PlusToken,
        right
      );
    }

    /**
     * x - y = (x ^ (~y+1)) - ((-2*x - 1) | (2*y - 1)) - 1
     */
    function method2(): BinaryExpression {
      const first: ParenthesizedExpression = factory.createParenthesizedExpression(
        factory.createBinaryExpression(
          {...minusExpression.left},
          SyntaxKind.CaretToken,
          factory.createParenthesizedExpression(
            factory.createBinaryExpression(
              factory.createPrefixUnaryExpression(
                SyntaxKind.TildeToken,
                {...minusExpression.right}
              ),
              SyntaxKind.PlusToken,
              factory.createNumericLiteral('1')
            )
          )
        )
      );

      const secondLeft: BinaryExpression = factory.createBinaryExpression(
        factory.createBinaryExpression(
          factory.createPrefixUnaryExpression(
            SyntaxKind.MinusToken,
            factory.createNumericLiteral('2')
          ),
          SyntaxKind.AsteriskToken,
          NodeUtils.createLowerExpression(minusExpression.left)
        ),
        SyntaxKind.MinusToken,
        factory.createNumericLiteral('1')
      );

      const secondRight: BinaryExpression = factory.createBinaryExpression(
        factory.createBinaryExpression(
          factory.createNumericLiteral('2'),
          SyntaxKind.AsteriskToken,
          NodeUtils.createLowerExpression(minusExpression.right)
        ),
        SyntaxKind.MinusToken,
        factory.createNumericLiteral('1')
      );

      const second: ParenthesizedExpression = factory.createParenthesizedExpression(
        factory.createBinaryExpression(
          factory.createParenthesizedExpression(secondLeft),
          SyntaxKind.BarToken,
          factory.createParenthesizedExpression(secondRight)
        )
      );

      return factory.createBinaryExpression(
        factory.createBinaryExpression(
          first,
          SyntaxKind.MinusToken,
          second
        ),
        SyntaxKind.MinusToken,
        factory.createNumericLiteral('1')
      );
    }

    /**
     * x - y = (x & ~y) - (~x & y)
     */
    function method3(): BinaryExpression {
      const left: ParenthesizedExpression = factory.createParenthesizedExpression(
        factory.createBinaryExpression(
          {...minusExpression.left},
          SyntaxKind.AmpersandToken,
          factory.createPrefixUnaryExpression(
            SyntaxKind.TildeToken,
            {...minusExpression.right}
          )
        )
      );

      const right: ParenthesizedExpression = factory.createParenthesizedExpression(
        factory.createBinaryExpression(
          factory.createPrefixUnaryExpression(
            SyntaxKind.TildeToken,
            {...minusExpression.left}
          ),
          SyntaxKind.AmpersandToken,
          {...minusExpression.right}
        )
      );

      return factory.createBinaryExpression(
        left,
        SyntaxKind.MinusToken,
        right
      );
    }

    /**
     * x - y = ~(~x + y)
     */
    function method4(): Expression {
      const inner: BinaryExpression = factory.createBinaryExpression(
        factory.createPrefixUnaryExpression(
          SyntaxKind.TildeToken,
          {...minusExpression.left}
        ),
        SyntaxKind.PlusToken,
        NodeUtils.createLowerExpression(minusExpression.right)
      );

      return factory.createPrefixUnaryExpression(
        SyntaxKind.TildeToken,
        factory.createParenthesizedExpression(inner)
      );
    }

    const methodList: (() => Expression)[] = [method1, method2, method3, method4];
    const mbaMethod: () => Expression = methodList[crypto.randomInt(methodList.length)];

    const decimalPart: BinaryExpression = getDecimalMinus();
    const highPart: BinaryExpression = getHigh32Minus();

    return factory.createBinaryExpression(
      factory.createBinaryExpression(
        mbaMethod(),
        SyntaxKind.PlusToken,
        highPart
      ),
      SyntaxKind.PlusToken,
      decimalPart
    );
  }

  private createCaretMBA(xorExpression: BinaryExpression): BinaryExpression {
    /**
     * x ^ y = (x | y) - (x & y)
     */
    function method1(): BinaryExpression {
      const left: ParenthesizedExpression = factory.createParenthesizedExpression(
        factory.createBinaryExpression(
          {...xorExpression.left},
          SyntaxKind.BarToken,
          {...xorExpression.right}
        )
      );

      const right: ParenthesizedExpression = factory.createParenthesizedExpression(
        factory.createBinaryExpression(
          {...xorExpression.left},
          SyntaxKind.AmpersandToken,
          {...xorExpression.right}
        )
      );

      return factory.createBinaryExpression(
        left,
        SyntaxKind.MinusToken,
        right
      );
    }

    /**
     * x ^ y = x + y - 2*(x & y)
     */
    function method2(): BinaryExpression {
      const left: BinaryExpression = factory.createBinaryExpression(
        NodeUtils.createLowerExpression(xorExpression.left),
        SyntaxKind.PlusToken,
        NodeUtils.createLowerExpression(xorExpression.right)
      );

      const right: BinaryExpression = factory.createBinaryExpression(
        factory.createNumericLiteral('2'),
        SyntaxKind.AsteriskToken,
        factory.createParenthesizedExpression(
          factory.createBinaryExpression(
            {...xorExpression.left},
            SyntaxKind.AmpersandToken,
            {...xorExpression.right}
          )
        )
      );

      return factory.createBinaryExpression(
        left,
        SyntaxKind.MinusToken,
        right
      );
    }

    const methodList: (() => BinaryExpression)[] = [method1, method2];
    const mbaMethod: () => BinaryExpression = methodList[crypto.randomInt(methodList.length)];
    return mbaMethod();
  }

  private createBarMBA(orExpression: BinaryExpression): BinaryExpression {
    /**
     * x | y = (x ^ y) ^ (x & y)
     */
    function method1(): BinaryExpression {
      const left: ParenthesizedExpression = factory.createParenthesizedExpression(
        factory.createBinaryExpression(
          {...orExpression.left},
          SyntaxKind.CaretToken,
          {...orExpression.right}
        )
      );

      const right: ParenthesizedExpression = factory.createParenthesizedExpression(
        factory.createBinaryExpression(
          {...orExpression.left},
          SyntaxKind.AmpersandToken,
          {...orExpression.right}
        )
      );

      return factory.createBinaryExpression(
        left,
        SyntaxKind.CaretToken,
        right
      );
    }

    /**
     * x | y = x + y - (x & y)
     */
    function method2(): BinaryExpression {
      const left: BinaryExpression = factory.createBinaryExpression(
        NodeUtils.createLowerExpression(orExpression.left),
        SyntaxKind.PlusToken,
        NodeUtils.createLowerExpression(orExpression.right)
      );

      const right: ParenthesizedExpression = factory.createParenthesizedExpression(
        factory.createBinaryExpression(
          {...orExpression.left},
          SyntaxKind.AmpersandToken,
          {...orExpression.right}
        )
      );

      return factory.createBinaryExpression(
        left,
        SyntaxKind.MinusToken,
        right
      );
    }

    /**
     * x | y = (x & y) | (x ^ y)
     */
    function method3(): BinaryExpression {
      const left: ParenthesizedExpression = factory.createParenthesizedExpression(
        factory.createBinaryExpression(
          {...orExpression.left},
          SyntaxKind.AmpersandToken,
          {...orExpression.right}
        )
      );

      const right: ParenthesizedExpression = factory.createParenthesizedExpression(
        factory.createBinaryExpression(
          {...orExpression.left},
          SyntaxKind.CaretToken,
          {...orExpression.right}
        )
      );

      return factory.createBinaryExpression(
        left,
        SyntaxKind.BarToken,
        right
      );
    }

    const methodList: (() => BinaryExpression)[] = [method1, method2, method3];
    const mbaMethod: () => BinaryExpression = methodList[crypto.randomInt(methodList.length)];
    return mbaMethod();
  }

  private createAmpersandMBA(andExpression: BinaryExpression): Expression {
    /**
     * x & y = ~(~x | ~y)
     */
    function method1(): Expression {
      const inner: BinaryExpression = factory.createBinaryExpression(
        factory.createPrefixUnaryExpression(
          SyntaxKind.TildeToken,
          {...andExpression.left}
        ),
        SyntaxKind.BarToken,
        factory.createPrefixUnaryExpression(
          SyntaxKind.TildeToken,
          {...andExpression.right}
        )
      );

      return factory.createPrefixUnaryExpression(
        SyntaxKind.TildeToken,
        factory.createParenthesizedExpression(
          inner
        )
      );
    }

    /**
     * x & y = x + y - (x | y)
     */
    function method2(): BinaryExpression {
      const left: BinaryExpression = factory.createBinaryExpression(
        NodeUtils.createLowerExpression(andExpression.left),
        SyntaxKind.PlusToken,
        NodeUtils.createLowerExpression(andExpression.right)
      );

      const right: ParenthesizedExpression = factory.createParenthesizedExpression(
        factory.createBinaryExpression(
          {...andExpression.left},
          SyntaxKind.BarToken,
          {...andExpression.right}
        )
      );

      return factory.createBinaryExpression(
        left,
        SyntaxKind.MinusToken,
        right
      );
    }

    /**
     * x & y = (x | y) - (~x & y) - (x & ~y)
     */
    function method3(): BinaryExpression {
      const first: ParenthesizedExpression = factory.createParenthesizedExpression(
        factory.createBinaryExpression(
          {...andExpression.left},
          SyntaxKind.BarToken,
          {...andExpression.right}
        )
      );

      const second: ParenthesizedExpression = factory.createParenthesizedExpression(
        factory.createBinaryExpression(
          factory.createPrefixUnaryExpression(
            SyntaxKind.TildeToken,
            {...andExpression.left}
          ),
          SyntaxKind.AmpersandToken,
          {...andExpression.right}
        )
      );

      const third: ParenthesizedExpression = factory.createParenthesizedExpression(
        factory.createBinaryExpression(
          {...andExpression.left},
          SyntaxKind.AmpersandToken,
          factory.createPrefixUnaryExpression(
            SyntaxKind.TildeToken,
            {...andExpression.right}
          )
        )
      );

      return factory.createBinaryExpression(
        factory.createBinaryExpression(
          first,
          SyntaxKind.MinusToken,
          second
        ),
        SyntaxKind.MinusToken,
        third
      );
    }

    /**
     * x & y = (x ^ ~y) & x
     */
    function method4(): BinaryExpression {
      const left: ParenthesizedExpression = factory.createParenthesizedExpression(
        factory.createBinaryExpression(
          {...andExpression.left},
          SyntaxKind.CaretToken,
          factory.createPrefixUnaryExpression(
            SyntaxKind.TildeToken,
            {...andExpression.right}
          )
        )
      );

      return factory.createBinaryExpression(
        left,
        SyntaxKind.AmpersandToken,
        {...andExpression.left}
      );
    }

    const methodList: (() => Expression)[] = [method1, method2, method3, method4];
    const mbaMethod: () => Expression = methodList[crypto.randomInt(methodList.length)];
    return mbaMethod();
  }
}
