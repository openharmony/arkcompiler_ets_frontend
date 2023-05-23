/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the License");
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
  forEachChild,
  isBinaryExpression,
  isBlock,
  isBreakOrContinueStatement,
  isClassDeclaration,
  isFunctionDeclaration,
  isFunctionLike,
  isIdentifier,
  isLabeledStatement,
  isPropertyAccessExpression,
  isSourceFile,
  isVariableDeclaration,
  setParentRecursive,
  SyntaxKind,
  visitEachChild
} from 'typescript';

import type {
  BinaryExpression,
  BinaryOperator,
  Block,
  Node,
  PropertyAccessExpression,
  SourceFile,
  Statement,
  TransformationContext,
  Transformer,
  TransformerFactory
} from 'typescript';

import type {TransformPlugin} from '../TransformPlugin';
import type {IOptions} from '../../configs/IOptions';
import {BogusBlockType} from '../../configs/IBogusControlFlowOption';
import type {IBogusControlFlowOption} from '../../configs/IBogusControlFlowOption';
import {NodeUtils} from '../../utils/NodeUtils';
import {collectExistNames, isObfsIgnoreNode} from '../../utils/TransformUtil';
import type {AbstractBogusControlHelper} from './AbstractBogusControlHelper';
import {SimpleBogusControlHelper} from './SimpleBogusControlHelper';
import type {INameGenerator, NameGeneratorOptions} from '../../generator/INameGenerator';
import {getNameGenerator, NameGeneratorType} from '../../generator/NameFactory';
import type {Hash} from 'crypto';

namespace secharmony {
  const createBogusControlFactory = function (option: IOptions): TransformerFactory<Node> {
    let profile: IBogusControlFlowOption | undefined = option?.mBogusControlFlow;
    if (!profile || !profile.mEnable || profile.mThreshold <= 0) {
      return null;
    }

    return bogusControlFactory;

    function bogusControlFactory(context: TransformationContext): Transformer<Node> {
      let blockMap: Map<string, Block> = new Map();
      let blockMapKeys: string[] = [];
      let bogusType: BogusBlockType = BogusBlockType.CURRENT_BLOCK_DEFORM;
      let sourceFile: SourceFile;
      let reservedNames: Set<string>;
      let nameGenerator: INameGenerator;

      return transformer;

      function transformer(node: Node): Node {
        if (!isSourceFile(node) || node.fileName.endsWith('.d.ts')) {
          return node;
        }

        sourceFile = node;

        // we only do bogus control flow with block
        if (!hasBlock(node)) {
          return node;
        }

        reservedNames = collectExistNames(sourceFile);
        const options: NameGeneratorOptions = {
          reservedNames: reservedNames
        };
        nameGenerator = getNameGenerator(NameGeneratorType.ORDERED, options);

        // if bogus block get from other block rename, extract all available blocks
        // javascript support current block deform and other block deform, typescript only
        // support current block deform.
        if (profile.mInsertBlockType === BogusBlockType.OTHER_BLOCK_RENAME && node.fileName.endsWith('.js')) {
          bogusType = BogusBlockType.OTHER_BLOCK_RENAME;
          getAvailableBlocks(node);
          for (const key of blockMap.keys()) {
            blockMapKeys.push(key);
          }
        }

        return setParentRecursive(bogusAst(node), true);
      }

      /**
       * Block is minimum process unit for us in bogus control flow,
       * we only inject code in the most inner Block
       * @param node
       */
      function bogusAst(node: Node): Node {
        if (profile.mSkipLoop && NodeUtils.isLoopStatement(node)) {
          return node;
        }

        if (!isSourceFile(node) && isObfsIgnoreNode(node, sourceFile)) {
          return node;
        }

        if (!isBlock(node)) {
          return visitEachChild(node, bogusAst, context);
        }

        const bogusNode: Block = visitEachChild(node, bogusAst, context);
        return bogusControlFlow(bogusNode);
      }

      function bogusControlFlow(node: Block): Block {
        if (NodeUtils.isContainForbidStringStatement(node) || node.statements.length <= 1) {
          return node;
        }

        // judge threshold
        const randomMaxValue: number = 100;
        const temp: number = crypto.randomInt(randomMaxValue);
        if (temp > randomMaxValue * profile.mThreshold) {
          return node;
        }

        let helper: AbstractBogusControlHelper = new SimpleBogusControlHelper(
          [...node.statements],
          profile.mUseOpaquePredicate,
          nameGenerator
        );

        const bogusBlock: Block = getBogusBlock(node, context);
        return helper.getBogusStruct(bogusBlock);
      }

      /**
       * random select other block or deform current block as bogus block
       */
      function getBogusBlock(node: Block, context: TransformationContext): Block {
        if (bogusType === BogusBlockType.CURRENT_BLOCK_DEFORM || blockMapKeys.length <= 1) {
          return deformBlock(node, context);
        }

        const randomMaxValue: number = 100;
        let index: number = crypto.randomInt(randomMaxValue) % blockMapKeys.length;
        if (getHash(NodeUtils.printNode(node, sourceFile)) === blockMapKeys[index]) {
          index = (index + 1) % blockMapKeys.length;
        }

        let bogusBlock: Block = blockMap.get(blockMapKeys[index]);
        // for randomness
        const deformedBlock: Block = deformBlock(bogusBlock, context);
        // rename identifier
        return renameIdentifier(deformedBlock, context, nameGenerator);
      }

      /**
       * get all blocks of current source file
       * @private
       */
      function getAvailableBlocks(node: Node): void {
        if (!isBlock(node)) {
          node.forEachChild((child) => {
            getAvailableBlocks(child);
          });

          return;
        }

        // remove special statement
        let deformedBlock: Block = removeSpecial(node);
        if (deformedBlock === null) {
          return;
        }

        // use printer to print block
        blockMap.set(getHash(NodeUtils.printNode(node, sourceFile)), deformedBlock);
        node.forEachChild((child) => {
          getAvailableBlocks(child);
        });
      }
    }
  };

  const TRANSFORMER_ORDER: number = 4;
  export let transformerPlugin: TransformPlugin = {
    'name': 'BogusControlTransformer',
    'createTransformerFactory': createBogusControlFactory,
    'order': (1 << TRANSFORMER_ORDER)
  };

  const hasBlock = function (node: Node): boolean {
    let flag: boolean = false;
    let visit = (inputNode): void => {
      if (flag) {
        return;
      }

      if (isBlock(inputNode)) {
        flag = true;
        return;
      }

      forEachChild(inputNode, visit);
    };

    visit(node);
    return flag;
  };

  /**
   * deform binary expression, example:
   *      a+b; -> a-b;
   *      a += b; -> a -= b;
   * @param expression
   * @private
   */
  const deformBinary = function (expression: BinaryExpression): BinaryExpression {
    const binaryOperators: SyntaxKind[] = [
      SyntaxKind.PlusToken, SyntaxKind.MinusToken, SyntaxKind.AsteriskToken,
      SyntaxKind.SlashToken, SyntaxKind.BarToken, SyntaxKind.CaretToken,
      SyntaxKind.AmpersandToken
    ];

    const kind: SyntaxKind = expression.operatorToken.kind;
    // plus need consider string value
    if (kind === SyntaxKind.PlusToken) {
      if (isBinaryExpression(expression.left) || isBinaryExpression(expression.right)) {
        return expression;
      }

      return factory.createBinaryExpression(
        factory.createBinaryExpression(
          {...expression.left},
          SyntaxKind.PlusToken,
          {...expression.right}
        ),
        SyntaxKind.PlusToken,
        {...expression.left}
      );
    }

    if (kind === SyntaxKind.PlusEqualsToken) {
      return factory.createBinaryExpression(
        {...expression.left},
        SyntaxKind.PlusEqualsToken,
        factory.createBinaryExpression(
          {...expression.left},
          SyntaxKind.PlusToken,
          {...expression.right}
        )
      );
    }

    let replaceKind: SyntaxKind = undefined;
    if (kind === SyntaxKind.MinusToken || kind === SyntaxKind.AsteriskToken ||
      kind === SyntaxKind.SlashToken || kind === SyntaxKind.BarToken ||
      kind === SyntaxKind.CaretToken || kind === SyntaxKind.AmpersandToken ||
      kind === SyntaxKind.PercentToken) {
      const randomMaxValue: number = 100;
      let index: number = crypto.randomInt(randomMaxValue) % binaryOperators.length;
      if (binaryOperators[index] === expression.operatorToken.kind) {
        index = (index + 1) % binaryOperators.length;
      }

      replaceKind = binaryOperators[index];
    }

    const binaryEqualOperators: SyntaxKind[] = [SyntaxKind.PlusEqualsToken, SyntaxKind.MinusEqualsToken,
      SyntaxKind.AsteriskEqualsToken, SyntaxKind.SlashEqualsToken, SyntaxKind.BarEqualsToken,
      SyntaxKind.CaretEqualsToken, SyntaxKind.AmpersandEqualsToken];
    if (kind === SyntaxKind.MinusEqualsToken || kind === SyntaxKind.AsteriskEqualsToken ||
      kind === SyntaxKind.SlashEqualsToken || kind === SyntaxKind.BarEqualsToken ||
      kind === SyntaxKind.CaretEqualsToken || kind === SyntaxKind.AmpersandEqualsToken) {
      const randomMaxValue: number = 100;
      let index: number = crypto.randomInt(randomMaxValue) % binaryEqualOperators.length;
      if (binaryEqualOperators[index] === expression.operatorToken.kind) {
        index = (index + 1) % binaryEqualOperators.length;
      }

      replaceKind = binaryEqualOperators[index];
    }

    const shiftOperators: SyntaxKind[] = [
      SyntaxKind.LessThanLessThanToken, SyntaxKind.GreaterThanGreaterThanToken,
      SyntaxKind.GreaterThanGreaterThanGreaterThanToken
    ];
    if (shiftOperators.includes(kind)) {
      const index: number = (shiftOperators.indexOf(kind) + 1) % shiftOperators.length;
      replaceKind = shiftOperators[index];
    }

    const equalOperators: SyntaxKind[] = [
      SyntaxKind.EqualsEqualsToken, SyntaxKind.ExclamationEqualsToken,
      SyntaxKind.EqualsEqualsEqualsToken, SyntaxKind.ExclamationEqualsEqualsToken,
      SyntaxKind.LessThanToken, SyntaxKind.LessThanEqualsToken,
      SyntaxKind.GreaterThanToken, SyntaxKind.GreaterThanEqualsToken,
    ];
    if (equalOperators.includes(kind)) {
      const index: number = (equalOperators.indexOf(kind) + 1) % equalOperators.length;
      replaceKind = equalOperators[index];
    }

    if (replaceKind === undefined) {
      return expression;
    }

    return factory.createBinaryExpression(
      {...expression.left},
      replaceKind as BinaryOperator,
      {...expression.right}
    );
  };

  /**
   * find special statement:
   *      return, break, continue, yield, await, super, this
   * @param statement
   * @private
   */
  const findSpecial = function (statement: Statement): boolean {
    let result: boolean = false;
    let visit = (node: Node): void => {
      if (result) {
        return;
      }

      if (isFunctionLike(node) ||
        NodeUtils.isLoopStatement(node)) {
        return;
      }

      if (isBreakOrContinueStatement(node)) {
        result = true;
        return;
      }

      if (node.kind === SyntaxKind.YieldKeyword ||
        node.kind === SyntaxKind.AwaitKeyword ||
        node.kind === SyntaxKind.SuperKeyword ||
        node.kind === SyntaxKind.ThisKeyword) {
        result = true;
        return;
      }

      forEachChild(node, visit);
    };

    visit(statement);
    return result;
  };

  /**
   * remove special statement of javascript
   * @param block
   * @private
   */
  const removeSpecial = function (block: Block): Block {
    const statements: Statement[] = [];
    for (const statement of block.statements) {
      if (findSpecial(statement)) {
        continue;
      }

      statements.push(statement);
    }

    if (statements.length === 0) {
      return null;
    }

    return factory.createBlock(statements, true);
  };

  /**
   * deform block
   * method:
   *      change binary expression;
   *      change true and false
   * @private
   */
  const deformBlock = function (originBlock: Block, context: TransformationContext): Block {
    // deform statement
    function visit(node: Node): Node {
      switch (node.kind) {
        case SyntaxKind.PropertyAccessExpression:
          return NodeUtils.changePropertyAccessToElementAccess(node as PropertyAccessExpression);
        case SyntaxKind.BinaryExpression:
          if (NodeUtils.isMostInnerBinary(node)) {
            return deformBinary(node as BinaryExpression);
          }
          break;
        case SyntaxKind.TrueKeyword:
          return factory.createFalse();
        case SyntaxKind.FalseKeyword:
          return factory.createTrue();
        case SyntaxKind.ContinueStatement:
          return factory.createBreakStatement();
        default:
          break;
      }

      return visitEachChild(node, visit, context);
    }

    return visit(originBlock) as Block;
  };

  const renameIdentifier = function (originBlock: Block, context: TransformationContext, nameGenerator: INameGenerator): Block {
    const nameCache: Map<string, string> = new Map<string, string>();
    const labelNameCache: Map<string, string> = new Map<string, string>();

    function visit(node: Node): Node {
      if (!isIdentifier(node) || !node.parent) {
        return visitEachChild(node, visit, context);
      }

      if (isLabeledStatement(node.parent)) {
        const deformedName: string = nameGenerator.getName();
        labelNameCache.set(node.text, deformedName);
        return factory.createIdentifier(deformedName);
      }

      if (isBreakOrContinueStatement(node.parent)) {
        const foundLabelName: string = labelNameCache.get(node.text);
        if (foundLabelName) {
          return factory.createIdentifier(foundLabelName);
        }

        return node;
      }

      if (isVariableDeclaration(node.parent) || isFunctionDeclaration(node.parent) || isClassDeclaration(node.parent)) {
        const deformedName: string = nameGenerator.getName();
        nameCache.set(node.text, deformedName);
        return factory.createIdentifier(deformedName);
      }

      if (isPropertyAccessExpression(node.parent)) {
        return node;
      }

      const foundName: string = nameCache.get(node.text);
      if (foundName) {
        return factory.createIdentifier(foundName);
      }

      return node;
    }

    return visit(originBlock) as Block;
  };

  /**
   * get hash value of string
   * @private
   */
  const getHash = function (str: string): string {
    const hash: Hash = crypto.createHash('sha256');
    return hash.update(str).digest('hex').toLowerCase();
  };
}

export = secharmony;
