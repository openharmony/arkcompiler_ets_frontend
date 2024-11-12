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
  isCaseClause,
  isDefaultClause,
  isElementAccessExpression,
  isExpressionStatement,
  isIdentifier,
  isModuleBlock,
  isPropertyAccessExpression,
  isSourceFile,
  setParentRecursive,
  visitEachChild
} from 'typescript';

import type {
  Block,
  CaseClause,
  DefaultClause,
  LeftHandSideExpression,
  ModuleBlock,
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
import {TransformerOrder} from '../TransformPlugin';
import { NodeUtils } from '../../utils/NodeUtils';
import { performancePrinter } from '../../ArkObfuscator';
import { EventList, endSingleFileEvent, startSingleFileEvent } from '../../utils/PrinterUtils';

namespace secharmony {
  export let transformerPlugin: TransformPlugin = {
    'name': 'disableConsolePlugin',
    'order': TransformerOrder.DISABLE_CONSOLE_TRANSFORMER,
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
        if (!isSourceFile(node) || NodeUtils.isDeclarationFile(node)) {
          return node;
        }

        startSingleFileEvent(EventList.REMOVE_CONSOLE, performancePrinter.timeSumPrinter);
        let resultAst: Node = visitAst(node);
        let parentNodes = setParentRecursive(resultAst, true);
        endSingleFileEvent(EventList.REMOVE_CONSOLE, performancePrinter.timeSumPrinter);
        return parentNodes;
      }

      /**
       * delete console log print expression, only support simple format like:
       *  - console.xxx();
       *  - console['xxx']();
       * @param node
       */
      function visitAst(node: Node): Node {
        const visitedAst = visitEachChild(node, visitAst, context);

        if (!(isSourceFile(node) || isBlock(node) || isModuleBlock(node) || isCaseClause(node) || isDefaultClause(node))) {
          return visitedAst;
        }

        //@ts-ignore
        const deletedStatements: Statement[] = deleteConsoleStatement(visitedAst.statements);

        if (isSourceFile(node)) {
          return factory.updateSourceFile(node, deletedStatements);
        } else if (isBlock(node)) {
          return factory.createBlock(deletedStatements, true);
        } else if (isModuleBlock(node)) {
          return factory.createModuleBlock(deletedStatements);
        } else if (isCaseClause(node)) {
          return factory.createCaseClause(node.expression, deletedStatements);
        } else {
          return factory.createDefaultClause(deletedStatements);
        }
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
