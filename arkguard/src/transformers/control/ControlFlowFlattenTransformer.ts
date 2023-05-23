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
  forEachChild,
  isBlock,
  isBreakOrContinueStatement, isCallExpression,
  isClassDeclaration, isExpressionStatement,
  isFunctionDeclaration,
  isFunctionLike, isSourceFile, isStringLiteral,
  isSwitchStatement,
  isVariableStatement,
  NodeFlags,
  setParentRecursive,
  SyntaxKind,
  visitEachChild
} from 'typescript';

import type {
  Block,
  Node,
  SourceFile,
  Statement,
  TransformationContext,
  Transformer,
  TransformerFactory
} from 'typescript';

import crypto from 'crypto';

import type {TransformPlugin} from '../TransformPlugin';
import type {IOptions} from '../../configs/IOptions';
import type {IControlFlowFatteningOption} from '../../configs/IControlFlowFatteningOption';
import {SimpleControlFlowFlattenHelper} from './SimpleControlFlowFlattenHelper';
import {ConfusedCharsFlattenHelper} from './ConfusedCharsFlattenHelper';
import {NodeUtils} from '../../utils/NodeUtils';
import {collectExistNames, isObfsIgnoreNode} from '../../utils/TransformUtil';

namespace secharmony {

  const MIN_TARGET_BLOCK_LENGTH: number = 4;
  const MAX_TARGET_BLOCK_LENGTH: number = 1000;

  const createCfgFlattenFactory = function (option: IOptions): TransformerFactory<Node> {
    let profile: IControlFlowFatteningOption | undefined = option?.mControlFlowFlattening;
    if (!profile || !profile.mEnable) {
      return null;
    }

    return cfgFlattenFactory;

    function cfgFlattenFactory(context: TransformationContext): Transformer<Node> {
      let narrowNames: string[] = option?.mNarrowFunctionNames ?? [];
      let threshold: number = profile?.mThreshold;
      let skipLoop: boolean = profile.mSkipLoop;
      let reservedNames: Set<string>;
      let sourceFile: SourceFile;

      return controlFlowFlattenTransformer;

      function controlFlowFlattenTransformer(node: Node): Node {
        if (!isSourceFile(node) || node.fileName.endsWith('.d.ts')) {
          return node;
        }

        sourceFile = node;
        reservedNames = collectExistNames(node);

        return setParentRecursive(controlFlowFlatten(node), true);
      }

      function controlFlowFlatten(node: Node): Node {
        if (skipLoop && NodeUtils.isLoopStatement(node)) {
          return node;
        }

        if (!isSourceFile(node) && isObfsIgnoreNode(node, sourceFile)) {
          return node;
        }

        if (!isBlock(node)) {
          return visitEachChild(node, controlFlowFlatten, context);
        }

        let newNode: Block = visitEachChild(node, controlFlowFlatten, context);
        if (ignoreFlatten(newNode.statements.length) ||
          NodeUtils.isContainNarrowNames(node, narrowNames)) {
          return newNode;
        }

        return factory.createBlock(obfuscateCfg(newNode), true);
      }

      function obfuscateCfg(node: Block): Statement[] {
        let finalStatements: Statement[] = [];
        const continuousStatement: Statement[] = [];

        // 1. filter continuous statements that can be flattened
        node.statements.forEach((child) => {
          if (!isForbiddenStatement(child)) {
            continuousStatement.push(child);
            return;
          }

          if (ignoreFlatten(continuousStatement.length)) {
            finalStatements = [...finalStatements, ...continuousStatement];
            finalStatements.push(child);
            continuousStatement.length = 0;
            return;
          }

          // 2. flatten continuous statements
          let helper: SimpleControlFlowFlattenHelper = profile?.mAdvance ?
            new ConfusedCharsFlattenHelper(continuousStatement, reservedNames) :
            new SimpleControlFlowFlattenHelper(continuousStatement, reservedNames);

          const flattenStatements: Statement[] = helper.getFlattenStruct();
          finalStatements = [...finalStatements, ...flattenStatements];
          finalStatements.push(child);
          continuousStatement.length = 0;
        });

        if (ignoreFlatten(continuousStatement.length)) {
          finalStatements = [...finalStatements, ...continuousStatement];
          continuousStatement.length = 0;
          return finalStatements;
        }

        // 2. flatten continuous statements
        let finalHelper: SimpleControlFlowFlattenHelper = profile?.mAdvance ?
          new ConfusedCharsFlattenHelper(continuousStatement, reservedNames) :
          new SimpleControlFlowFlattenHelper(continuousStatement, reservedNames);

        const flatten: Statement[] = finalHelper.getFlattenStruct();
        finalStatements = [...finalStatements, ...flatten];
        return finalStatements;
      }

      function ignoreFlatten(statementsLen: number): boolean {
        if (statementsLen < MIN_TARGET_BLOCK_LENGTH || statementsLen > MAX_TARGET_BLOCK_LENGTH) {
          return true;
        }

        // judge threshold
        const randomMaxValue: number = 100;
        const temp: number = crypto.randomInt(randomMaxValue);
        return temp > randomMaxValue * threshold;
      }

      /**
       * is break or continue statement contained
       * @param statement
       */
      function isContainForbidBreakOrContinue(statement: Statement): boolean {
        let result: boolean = false;
        let visit = (n: Node): void => {
          if (isFunctionLike(n) ||
            isSwitchStatement(n) ||
            NodeUtils.isLoopStatement(n)) {
            return;
          }

          if (isBreakOrContinueStatement(n)) {
            result = true;
            return;
          }

          forEachChild(n, visit);
        };

        forEachChild(statement, visit);
        return result;
      }

      /**
       * is statement forbidden in control flow flatten, list of forbidden:
       *   - let/const declaration;
       *   - function declaration;
       *   - class declaration;
       *   - 'use strict' like statement;
       *   - break/continue;
       * @param statement
       */
      function isForbiddenStatement(statement: Statement): boolean {
        if (isVariableStatement(statement)) {
          return !!(statement.declarationList.flags & NodeFlags.Const ||
            statement.declarationList.flags & NodeFlags.Let);
        }

        if (isExpressionStatement(statement)) {
          if (isStringLiteral(statement.expression)) {
            return true;
          }

          return isCallExpression(statement.expression) &&
            statement.expression.expression.kind === SyntaxKind.SuperKeyword;
        }

        return isFunctionDeclaration(statement) ||
          isClassDeclaration(statement) ||
          isContainForbidBreakOrContinue(statement);
      }
    }
  };

  const TRANSFORMER_ORDER: number = 7;
  export let transformerPlugin: TransformPlugin = {
    'name': 'ControlFlowFlattenTransformer',
    'createTransformerFactory': createCfgFlattenFactory,
    'order': (1 << TRANSFORMER_ORDER)
  };
}

export = secharmony;
