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

import * as crypto from 'crypto';

import {
  factory,
  isBinaryExpression,
  isCallExpression,
  isDecorator,
  isElementAccessExpression,
  isIdentifier,
  isPropertyAccessExpression,
  isSourceFile,
  NodeFlags,
  setParentRecursive,
  SyntaxKind,
  visitEachChild
} from 'typescript';

import type {
  BinaryExpression,
  BinaryOperator,
  Block,
  CallExpression,
  CaseOrDefaultClause,
  Expression,
  FunctionDeclaration,
  Identifier,
  Node,
  ParameterDeclaration,
  PropertyAccessExpression,
  PropertyAssignment, SourceFile,
  Statement, SwitchStatement,
  TransformationContext,
  Transformer,
  TransformerFactory,
  VariableStatement
} from 'typescript';

import type {TransformPlugin} from '../TransformPlugin';
import type {IOptions} from '../../configs/IOptions';
import {InstructionObfsMethod} from '../../configs/IInstructionObfuscationOption';
import type {IInstructionObfuscationOption} from '../../configs/IInstructionObfuscationOption';
import {InstructionHelper} from './InstructionObfsHelper';
import {NodeUtils} from '../../utils/NodeUtils';
import {getNameGenerator, NameGeneratorType} from '../../generator/NameFactory';
import type {INameGenerator, NameGeneratorOptions} from '../../generator/INameGenerator';
import {collectExistNames, isObfsIgnoreNode} from '../../utils/TransformUtil';

namespace secharmony {
  const createInstructionObfuscationFactory = function (option: IOptions): TransformerFactory<Node> {
    let profile: IInstructionObfuscationOption | undefined = option?.mInstructionObfuscation;
    if (!profile || !profile.mEnable || profile.mThreshold <= 0) {
      return null;
    }

    return instructionObfuscationFactory;

    function instructionObfuscationFactory(context: TransformationContext): Transformer<Node> {
      const skipLoop: boolean = profile.mSkipLoop;
      let instructionHelper: InstructionHelper;
      let narrowNames: string[] = option?.mNarrowFunctionNames ?? [];
      // for call expression
      let varName: string;
      let pairArray: PropertyAssignment[] = [];
      let reservedNames: Set<string>;
      let reservedIdentifiers: Set<string>;
      let sourceFile: SourceFile;

      // for binary expression
      let replaceMethod: InstructionObfsMethod = profile.mInstructionObfsMethod;
      const methodTypeMap: Map<SyntaxKind, string> = new Map();
      let deformFuncName: string;
      const seed: string = '0x' + crypto.randomBytes(1).toString('hex');
      let simpleDeformed: boolean = false;

      return transformer;

      function transformer(node: Node): Node {
        if (!isSourceFile(node) || node.fileName.endsWith('.d.ts')) {
          return node;
        }

        sourceFile = node;
        reservedIdentifiers = collectExistNames(node);

        const options: NameGeneratorOptions = {
          reservedNames: reservedIdentifiers
        };
        const nameGenerator: INameGenerator = getNameGenerator(NameGeneratorType.ORDERED, options);
        instructionHelper = new InstructionHelper(nameGenerator);
        varName = nameGenerator.getName();
        deformFuncName = nameGenerator.getName();
        const functionDeclare: FunctionDeclaration = createSimpleDeformFunction(deformFuncName, seed);

        let obfuscatedAst: Node = visitAst(node);

        reservedNames = instructionHelper.getReservedIdentifiers();
        if (reservedNames.size > 0) {
          obfuscatedAst = changeReservedNamesAccess(obfuscatedAst);
        }

        if (!isSourceFile(obfuscatedAst)) {
          return node;
        }

        let newStatements: Statement[] = [...obfuscatedAst.statements];
        if (simpleDeformed) {
          newStatements = NodeUtils.randomInsertStatements(newStatements, functionDeclare);
        }

        if (pairArray.length > 0) {
          const initStatement: VariableStatement = instructionHelper.createCallMapStatement(varName, pairArray);
          newStatements = [initStatement, ...newStatements];
        }

        // must use update, don't create here, otherwise will encounter an issue for printer.
        const newAst: SourceFile = factory.updateSourceFile(node, newStatements);
        return setParentRecursive(newAst, true);
      }

      function visitAst(node: Node): Node {
        if (isDecorator(node)) {
          return node;
        }

        if (skipLoop && NodeUtils.isLoopStatement(node)) {
          return node;
        }

        if (!isSourceFile(node) && isObfsIgnoreNode(node, sourceFile)) {
          return node;
        }

        // only replace most inner instruction
        if ((!isCallExpression(node) || !NodeUtils.isMostInnerCallExpression(node)) &&
          (!isBinaryExpression(node) || !NodeUtils.isMostInnerBinary(node))) {
          return visitEachChild(node, visitAst, context);
        }

        const newNode: BinaryExpression | CallExpression = visitEachChild(node, visitAst, context);
        return replaceInstruction(newNode);
      }

      /**
       * change property access to element access of reserved names
       * @param node
       */
      function changeReservedNamesAccess(node: Node): Node {
        if (!isPropertyAccessExpression(node)) {
          return visitEachChild(node, changeReservedNamesAccess, context);
        }

        if (!isIdentifier(node.expression)) {
          return visitEachChild(node, changeReservedNamesAccess, context);
        }

        if (!reservedNames.has(node.expression.escapedText.toString())) {
          return node;
        }

        const newNode: PropertyAccessExpression = visitEachChild(node, changeReservedNamesAccess, context);
        return NodeUtils.changePropertyAccessToElementAccess(newNode);
      }

      function simpleDeformBinary(binaryExpression: BinaryExpression): Expression {
        if (methodTypeMap.get(binaryExpression.operatorToken.kind) === undefined) {
          return binaryExpression;
        }

        if (binaryExpression.operatorToken.kind === SyntaxKind.AmpersandAmpersandToken ||
          binaryExpression.operatorToken.kind === SyntaxKind.BarBarToken) {
          return binaryExpression;
        }

        const type: string = methodTypeMap.get(binaryExpression.operatorToken.kind);
        const HEX_RADIX: number = 16;
        const fakeValue: number = parseInt(type, HEX_RADIX) - parseInt(seed, HEX_RADIX);
        let fakeValueHexStr: string = '0x' + (Math.abs(fakeValue)).toString(HEX_RADIX);
        if (fakeValue < 0) {
          fakeValueHexStr = '-' + fakeValueHexStr;
        }

        simpleDeformed = true;
        return factory.createCallExpression(
          factory.createIdentifier(deformFuncName),
          undefined,
          [
            {...binaryExpression.left},
            {...binaryExpression.right},
            factory.createNumericLiteral(fakeValueHexStr)
          ]
        );
      }

      function replaceInstruction(node: Node): Node {
        // judge threshold
        const RANDOM_MAX: number = 100;
        const temp: number = crypto.randomInt(RANDOM_MAX);
        if (temp > RANDOM_MAX * profile.mThreshold) {
          return node;
        }

        if (isCallExpression(node)) {
          if (isPropertyAccessExpression(node.expression) ||
            isElementAccessExpression(node.expression) ||
            !isIdentifier(node.expression)) {
            return node;
          }

          if (narrowNames.includes((node.expression as Identifier).text)) {
            return node;
          }

          return instructionHelper.deformCallExpression(node, varName, pairArray);
        }

        if (isBinaryExpression(node)) {
          if (replaceMethod !== InstructionObfsMethod.MBA_EXPRESSION) {
            return simpleDeformBinary(node);
          }

          const replacedBinary: Expression = instructionHelper.obfuscateBinaryExpression(node);
          if (replacedBinary !== node) {
            return replacedBinary;
          }

          return simpleDeformBinary(node);
        }

        return node;
      }

      function generateMethodTypeMap(): void {
        const methodList: SyntaxKind[] = [
          SyntaxKind.PlusToken, SyntaxKind.MinusToken, SyntaxKind.AsteriskToken,
          SyntaxKind.SlashToken, SyntaxKind.AmpersandToken, SyntaxKind.BarToken,
          SyntaxKind.CaretToken, SyntaxKind.BarBarToken, SyntaxKind.AmpersandAmpersandToken,
          SyntaxKind.EqualsEqualsToken, SyntaxKind.ExclamationEqualsToken,
          SyntaxKind.EqualsEqualsEqualsToken, SyntaxKind.ExclamationEqualsEqualsToken,
          SyntaxKind.LessThanToken, SyntaxKind.LessThanEqualsToken,
          SyntaxKind.GreaterThanToken, SyntaxKind.GreaterThanEqualsToken,
          SyntaxKind.LessThanLessThanToken, SyntaxKind.GreaterThanGreaterThanToken,
          SyntaxKind.GreaterThanGreaterThanGreaterThanToken,
          SyntaxKind.PercentToken, SyntaxKind.InstanceOfKeyword,
          SyntaxKind.InKeyword
        ];

        const options: NameGeneratorOptions = {
          hexLength: 2,
          hexWithPrefixSuffix: false
        };

        const typeGenerator: INameGenerator = getNameGenerator(NameGeneratorType.HEX, options);
        methodList.forEach((method) => {
          methodTypeMap.set(method, '0x' + typeGenerator.getName());
        });
      }

      /**
       * create simple deform function of calculate binary expression
       * function parameter use common name because name obfuscate will be done after this transformer
       * index transform prototype: x+y = (x|y) + (x&y)
       * @param functionName
       * @param seed
       * @private
       */
      function createSimpleDeformFunction(functionName: string, seed: string): FunctionDeclaration {
        const parameters: ParameterDeclaration[] = [
          factory.createParameterDeclaration(
            undefined,
            undefined,
            undefined,
            factory.createIdentifier('left')
          ),
          factory.createParameterDeclaration(
            undefined,
            undefined,
            undefined,
            factory.createIdentifier('right')
          ),
          factory.createParameterDeclaration(
            undefined,
            undefined,
            undefined,
            factory.createIdentifier('type')
          )
        ];

        const valueDeclare: VariableStatement = factory.createVariableStatement(
          undefined,
          factory.createVariableDeclarationList(
            [
              factory.createVariableDeclaration(
                factory.createIdentifier('value'),
                undefined,
                undefined,
                factory.createBinaryExpression(
                  factory.createParenthesizedExpression(
                    factory.createBinaryExpression(
                      factory.createNumericLiteral(seed),
                      SyntaxKind.BarToken,
                      factory.createIdentifier('type')
                    )
                  ),
                  SyntaxKind.PlusToken,
                  factory.createParenthesizedExpression(
                    factory.createBinaryExpression(
                      factory.createNumericLiteral(seed),
                      SyntaxKind.AmpersandToken,
                      factory.createIdentifier('type')
                    )
                  )
                )
              )
            ],
            NodeFlags.Const
          )
        );

        const caseClauses: CaseOrDefaultClause[] = [];
        generateMethodTypeMap();
        for (const method of methodTypeMap.keys()) {
          caseClauses.push(
            factory.createCaseClause(
              factory.createNumericLiteral(methodTypeMap.get(method)),
              [
                factory.createReturnStatement(
                  factory.createBinaryExpression(
                    factory.createIdentifier('left'),
                    method as BinaryOperator,
                    factory.createIdentifier('right')
                  )
                )
              ]
            )
          );
        }

        caseClauses.push(
          factory.createDefaultClause(
            [
              factory.createReturnStatement(
                factory.createNumericLiteral(seed)
              )
            ]
          )
        );

        const switchStatement: SwitchStatement = factory.createSwitchStatement(
          factory.createIdentifier('value'),
          factory.createCaseBlock(caseClauses)
        );

        const body: Block = factory.createBlock(
          [
            valueDeclare,
            switchStatement
          ],
          true
        );

        return factory.createFunctionDeclaration(
          undefined,
          undefined,
          undefined,
          factory.createIdentifier(functionName),
          undefined,
          parameters,
          undefined,
          body
        );
      }
    }
  };

  const TRANSFORMER_ORDER: number = 5;
  export let transformerPlugin: TransformPlugin = {
    'name': 'InstructionObfuscationTransformer',
    'createTransformerFactory': createInstructionObfuscationFactory,
    'order': (1 << TRANSFORMER_ORDER)
  };
}

export = secharmony;
