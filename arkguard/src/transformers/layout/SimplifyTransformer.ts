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
  isBlock,
  isExpressionStatement,
  isReturnStatement,
  isSourceFile,
  isVariableStatement,
  setParentRecursive,
  SyntaxKind,
  visitEachChild,
  isStringLiteral,
} from 'typescript';

import type {
  ExpressionStatement,
  Node,
  NodeFlags,
  Statement,
  TransformationContext,
  Transformer,
  TransformerFactory,
  VariableDeclaration,
  VariableStatement,
  ModifiersArray,
  SourceFile,
  Block,
  Expression
} from 'typescript';

import type {IOptions} from '../../configs/IOptions';
import type {TransformPlugin} from '../TransformPlugin';
import {isCommentedNode, isSuperCallStatement} from '../../utils/TransformUtil';

namespace secharmony {
  const TRANSFORMER_ORDER: number = 5;
  export let transformerPlugin: TransformPlugin = {
    'name': 'simplifyPlugin',
    'order': (1 << TRANSFORMER_ORDER),
    'createTransformerFactory': createSimplifyFactory
  };

  export function createSimplifyFactory(option: IOptions): TransformerFactory<Node> {
    if (!option.mSimplify) {
      return null;
    }

    return simplifyFactory;

    function simplifyFactory(context: TransformationContext): Transformer<Node> {
      const MIN_STATEMENTS_LEN = 2;
      let sourceFile: SourceFile;
      return transformer;

      function transformer(node: Node): Node {
        if (!isSourceFile(node) || node.fileName.endsWith('.d.ts')) {
          return node;
        }

        sourceFile = node;
        return setParentRecursive(visitStatements(node), true);
      }

      function visitStatements(node: Node): Node {
        if (!isSourceFile(node) && !isBlock(node)) {
          return visitEachChild(node, visitStatements, context);
        }

        const simplified: SourceFile | Block = visitEachChild(node, visitStatements, context);
        if (node.statements.length < MIN_STATEMENTS_LEN) {
          return node;
        }

        return simplifyStatements(simplified);
      }

      /**
       * use variable statement merge and expression merge to simplify code
       * @param node
       */
      function simplifyStatements(node: Node): Node {
        if (!isSourceFile(node) && !isBlock(node)) {
          return node;
        }

        let simplifiedStatements: Statement[] = [];
        const continuousStatements: Statement[] = [];
        let nodeFlag: NodeFlags = undefined;
        let modifiers: ModifiersArray = undefined;
        let preType: SyntaxKind | undefined = undefined;

        function mergeArray(): void {
          if (continuousStatements.length < MIN_STATEMENTS_LEN) {
            simplifiedStatements = [...simplifiedStatements, ...continuousStatements];
            return;
          }

          if (preType === SyntaxKind.VariableStatement) {
            simplifiedStatements.push(mergeVariableStatements(continuousStatements as VariableStatement[]));
            return;
          }

          if (preType === SyntaxKind.ExpressionStatement) {
            simplifiedStatements.push(mergeExpression(continuousStatements as ExpressionStatement[]));
          }
        }

        function doMerge(currentType: SyntaxKind | undefined, child: Statement | undefined): void {
          if (preType === currentType) {
            if (preType !== SyntaxKind.VariableStatement) {
              return;
            }

            if (nodeFlag === (child as VariableStatement).declarationList.flags) {
              if (!modifiers && !child.modifiers) {
                return;
              }

              let isSame: boolean = true;
              if (modifiers && child.modifiers && modifiers.length === child.modifiers.length) {
                modifiers.forEach((modifier, index) => {
                  if (modifier.kind !== child.modifiers[index].kind) {
                    isSame = false;
                  }
                });
              } else {
                isSame = false;
              }

              if (isSame) {
                return;
              }
            }

            mergeArray();
            nodeFlag = (child as VariableStatement).declarationList.flags;
            modifiers = child.modifiers;
            continuousStatements.length = 0;
            return;
          }

          if (preType === SyntaxKind.VariableStatement) {
            nodeFlag = undefined;
            modifiers = undefined;
            mergeArray();
          } else if (preType === SyntaxKind.ExpressionStatement) {
            mergeArray();
          }

          continuousStatements.length = 0;
          preType = currentType;
        }

        node.statements.forEach((child) => {
          if (isCommentedNode(child, sourceFile) ||
            (isExpressionStatement(child) && isStringLiteral(child.expression)) ||
            isSuperCallStatement(child)
          ) {
            doMerge(undefined, undefined);
            simplifiedStatements.push(child);
            return;
          }

          if (isVariableStatement(child)) {
            doMerge(SyntaxKind.VariableStatement, child);
            continuousStatements.push(child);
            nodeFlag = child.declarationList.flags;
            modifiers = child.modifiers;
            return;
          }

          if (isExpressionStatement(child)) {
            doMerge(SyntaxKind.ExpressionStatement, child);
            continuousStatements.push(child);
            return;
          }

          if (isReturnStatement(child) && child.expression !== undefined) {
            doMerge(SyntaxKind.ExpressionStatement, child);
            continuousStatements.push(child);
            doMerge(undefined, undefined);
            return;
          }

          // do merge on continuous stopped
          doMerge(undefined, child);
          simplifiedStatements.push(child);
        });

        doMerge(undefined, undefined);

        if (isSourceFile(node)) {
          return factory.updateSourceFile(node, simplifiedStatements);
        }

        return factory.createBlock(simplifiedStatements, true);
      }

      /**
       * merge variable statement, need same type and same modifier variable and continuous
       * @param variableStatements
       */
      function mergeVariableStatements(variableStatements: VariableStatement[]): VariableStatement {
        let variableDeclarations: VariableDeclaration[] = [];
        variableStatements.forEach((statement) => {
          variableDeclarations = [...variableDeclarations, ...statement.declarationList.declarations];
        });

        return factory.createVariableStatement(
          variableStatements[0].modifiers,
          factory.createVariableDeclarationList(
            variableDeclarations,
            variableStatements[0].declarationList.flags
          )
        );
      }

      /**
       * merge expression, include:
       *   - continuous expression like a=a+1; b=b+1;
       */
      function mergeExpression(expressionStatements: ExpressionStatement[]): Statement {
        let pos: number = 1;
        let expression: Expression = expressionStatements[0].expression;
        const statementsLength: number = expressionStatements.length;
        while (pos < statementsLength) {
          expression = factory.createBinaryExpression(
            expression,
            SyntaxKind.CommaToken,
            expressionStatements[pos].expression
          );
          pos += 1;
        }

        if (isReturnStatement(expressionStatements[statementsLength - 1])) {
          return factory.createReturnStatement(expression);
        }

        return factory.createExpressionStatement(expression);
      }
    }
  }
}

export = secharmony;
