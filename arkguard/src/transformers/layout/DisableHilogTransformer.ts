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
import {OhPackType, isCommentedNode} from '../../utils/TransformUtil';
import {findOhImportStatement} from '../../utils/OhsUtil';

namespace secharmony {
  const TRANSFORMER_ORDER: number = 2;
  export let transformerPlugin: TransformPlugin = {
    'name': 'disableHilogPlugin',
    'order': (1 << TRANSFORMER_ORDER),
    'createTransformerFactory': createDisableHilogFactory
  };

  export function createDisableHilogFactory(option: IOptions): TransformerFactory<Node> {
    if (!option.mDisableHilog) {
      return null;
    }

    return disableHilogFactory;

    function disableHilogFactory(context: TransformationContext): Transformer<Node> {
      let sourceFile: SourceFile;
      return transformer;

      function transformer(node: Node): Node {
        if (!isSourceFile(node) || node.fileName.endsWith('.d.ts')) {
          return node;
        }

        sourceFile = node;
        let resultAst: Node = visitAst(node);
        return setParentRecursive(resultAst, true);
      }

      function visitAst(node: Node): Node {
        if (isSourceFile(node)) {
          const visitedAst: SourceFile = visitEachChild(node, visitAst, context);
          const deletedStatements: Statement[] = deleteHilogStatement(visitedAst.statements);

          return factory.updateSourceFile(node, deletedStatements);
        }

        if (!isBlock(node)) {
          return visitEachChild(node, visitAst, context);
        }

        const visitedBlock: Block = visitEachChild(node, visitAst, context);
        const newStatements: Statement[] = deleteHilogStatement(visitedBlock.statements);

        return factory.createBlock(newStatements, true);
      }

      function deleteHilogStatement(statements: NodeArray<Statement>): Statement[] {
        const reservedStatements: Statement[] = [];
        statements.forEach((child) => {
          if (isSimpleHilogStatement(child)) {
            return;
          }

          if (isHilogImportStatement(child)) {
            if (isCommentedNode(child, sourceFile)) {
              reservedStatements.push(child);
            }

            return;
          }

          reservedStatements.push(child);
        });

        return reservedStatements;
      }

      function isHilogImportStatement(node: Statement): boolean {
        const ohPackType: OhPackType = findOhImportStatement(node, '@ohos.hilog');
        return ohPackType !== OhPackType.NONE;
      }

      function isSimpleHilogStatement(node: Statement): boolean {
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
          if (isIdentifier(expressionCalled.expression) && expressionCalled.expression.text === 'hilog') {
            return true;
          }
        }

        if (isElementAccessExpression(expressionCalled) && expressionCalled.expression) {
          if (isIdentifier(expressionCalled.expression) && expressionCalled.expression.text === 'hilog') {
            return true;
          }
        }

        return false;
      }
    }
  }
}

export = secharmony;
