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
  isCallExpression,
  isElementAccessExpression,
  isExpressionStatement,
  isIdentifier,
  isPropertyAccessExpression,
  isSourceFile,
  setParentRecursive,
  visitEachChild
} from 'typescript';

import type {
  Block,
  LeftHandSideExpression,
  Node,
  NodeArray,
  SourceFile,
  Statement,
  TransformationContext,
  Transformer,
  TransformerFactory
} from 'typescript';

import type {IOptions} from '../../configs/IOptions';
import type {TransformPlugin} from '../TransformPlugin';

namespace secharmony {
  const TRANSFORMER_ORDER: number = 1;
  export let transformerPlugin: TransformPlugin = {
    'name': 'disableConsolePlugin',
    'order': (1 << TRANSFORMER_ORDER),
    'createTransformerFactory': createDisableConsoleFactory
  };

  export function createDisableConsoleFactory(option: IOptions): TransformerFactory<Node> {
    if (!option.mDisableConsole) {
      return null;
    }

    return disableConsoleFactory;

    function disableConsoleFactory(context: TransformationContext): Transformer<Node> {
      return transformer;

      function transformer(node: Node): Node {
        if (!isSourceFile(node) || node.fileName.endsWith('.d.ts')) {
          return node;
        }

        let resultAst: Node = visitAst(node);
        return setParentRecursive(resultAst, true);
      }

      /**
       * delete console log print expression, only support simple format like:
       *  - console.xxx();
       *  - console['xxx']();
       * @param node
       */
      function visitAst(node: Node): Node {
        if (isSourceFile(node)) {
          const visitedAst: SourceFile = visitEachChild(node, visitAst, context);
          const deletedStatements: Statement[] = deleteConsoleStatement(visitedAst.statements);

          return factory.updateSourceFile(node, deletedStatements);
        }

        if (!isBlock(node)) {
          return visitEachChild(node, visitAst, context);
        }

        const visitedBlock: Block = visitEachChild(node, visitAst, context);
        const newStatements: Statement[] = deleteConsoleStatement(visitedBlock.statements);

        return factory.createBlock(newStatements, true);
      }

      function deleteConsoleStatement(statements: NodeArray<Statement>): Statement[] {
        const reservedStatements: Statement[] = [];
        statements.forEach((child) => {
          if (!isSimpleConsoleStatement(child)) {
            reservedStatements.push(child);
          }
        });

        return reservedStatements;
      }

      function isSimpleConsoleStatement(node: Statement): boolean {
        if (!isExpressionStatement(node)) {
          return false;
        }

        if (!node.expression || !isCallExpression(node.expression)) {
          return false;
        }

        const expressionCalled: LeftHandSideExpression = node.expression.expression;
        if (!expressionCalled) {
          return false;
        }

        if (isPropertyAccessExpression(expressionCalled) && expressionCalled.expression) {
          if (isIdentifier(expressionCalled.expression) && expressionCalled.expression.text === 'console') {
            return true;
          }
        }

        if (isElementAccessExpression(expressionCalled) && expressionCalled.expression) {
          if (isIdentifier(expressionCalled.expression) && expressionCalled.expression.text === 'console') {
            return true;
          }
        }

        return false;
      }
    }
  }
}

export = secharmony;
