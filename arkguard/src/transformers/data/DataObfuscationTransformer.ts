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
  factory, isElementAccessExpression,
  isEnumDeclaration, isExportDeclaration,
  isExpressionStatement, isImportDeclaration,
  isImportEqualsDeclaration,
  isSourceFile,
  isStringLiteralLike, isTypeAliasDeclaration,
  setParentRecursive,
  visitEachChild,
} from 'typescript';

import type {
  Node,
  SourceFile,
  Statement,
  TransformationContext,
  Transformer,
  TransformerFactory
} from 'typescript';

import crypto from 'crypto';

import type {
  IBooleanOption,
  IDataObfuscationOption,
  INumberOption,
  IStringOption
} from '../../configs/IDataObfuscationOption';

import type {TransformPlugin} from '../TransformPlugin';
import type {IOptions} from '../../configs/IOptions';
import {SimpleStringObfuscateHelper} from './SimpleStringObfuscateHelper';
import {NodeUtils} from '../../utils/NodeUtils';
import type {INameGenerator, NameGeneratorOptions} from '../../generator/INameGenerator';
import {collectExistNames, isObfsIgnoreNode} from '../../utils/TransformUtil';
import {getNameGenerator, NameGeneratorType} from '../../generator/NameFactory';
import {BoolObfuscationHelper} from './BoolObfuscationHelper';
import {NumberObfuscationHelper} from './NumberObfuscationHelper';

/**
 * Data obfuscation must follow attribute name obfuscation. Because if data is obfuscated and strings are 
 * extracted onto arrays, attribute name obfuscation may result in some strings not being obfuscated.
 */
namespace secharmony {
  const RANDOM_MAX: number = 100;

  const createDataObfuscationFactory = function (options: IOptions): TransformerFactory<Node> {
    let profile: IDataObfuscationOption | undefined = options?.mDataObfuscation;
    if (!profile || !profile.mEnable) {
      return null;
    }

    return dataObfuscationFactory;

    function dataObfuscationFactory(context: TransformationContext): Transformer<Node> {
      let boolOption: IBooleanOption = profile.mBooleanOption;
      let stringOption: IStringOption = profile.mStringOption;
      let numberOption: INumberOption = profile.mNumberOption;
      let nameGenerator: INameGenerator;
      let sourceFile: SourceFile;

      return transformer;

      function transformer(node: Node): Node {
        if (!isSourceFile(node) || node.fileName.endsWith('.d.ts')) {
          return node;
        }

        sourceFile = node;
        let newNode: SourceFile = node;

        if (boolOption && boolOption.mEnable) {
          newNode = doBoolTransform(newNode) as SourceFile;
        }

        if (numberOption && numberOption.mEnable) {
          newNode = doNumberTransform(newNode) as SourceFile;
        }

        if (stringOption && stringOption.mEnable) {
          const reservedNames: Set<string> = collectExistNames(node);
          const generatorOptions: NameGeneratorOptions = {
            reservedNames: reservedNames
          };

          nameGenerator = getNameGenerator(NameGeneratorType.ORDERED, generatorOptions);
          newNode = doStringTransform(newNode, nameGenerator);
        }

        return newNode;
      }

      function doBoolTransform(node: Node): Node {
        if (boolOption.mSkipLoop && NodeUtils.isLoopStatement(node)) {
          return node;
        }

        if (!BoolObfuscationHelper.isBooleanLiteral(node)) {
          return visitEachChild(node, doBoolTransform, context);
        }

        // threshold check
        const temp: number = crypto.randomInt(RANDOM_MAX);
        if (temp > RANDOM_MAX * boolOption.mThreshold) {
          return node;
        }

        if (BoolObfuscationHelper.isTrueKeyword(node)) {
          return BoolObfuscationHelper.createTrueObfuscation();
        }

        return BoolObfuscationHelper.createFalseObfuscation();
      }

      function doNumberTransform(node: Node): Node {
        if (numberOption.mSkipLoop && NodeUtils.isLoopStatement(node)) {
          return node;
        }

        if (!NumberObfuscationHelper.isTargetNumberNode(node)) {
          return visitEachChild(node, doNumberTransform, context);
        }

        // threshold check
        const temp: number = crypto.randomInt(RANDOM_MAX);
        if (temp > RANDOM_MAX * numberOption.mThreshold) {
          return node;
        }

        return NumberObfuscationHelper.convertNumberToExpression(node);
      }

      function doStringTransform(node: SourceFile, generator: INameGenerator): SourceFile {
        let helper: SimpleStringObfuscateHelper = new SimpleStringObfuscateHelper(stringOption, generator);
        helper.collectLiterals(node);

        sourceFile = node as SourceFile;
        let source: Node = stringVisitor(node);
        let newStatements: Statement[] = NodeUtils.randomInsertStatements(
          NodeUtils.randomInsertStatements([...(source as SourceFile).statements],
            helper.prepareIndexFunctionStruct()),
          helper.prepareArrayFunctionStruct());

        return setParentRecursive(factory.updateSourceFile(source as SourceFile, newStatements), true);

        function stringVisitor(node: Node): Node {
          if (stringOption.mSkipLoop && NodeUtils.isLoopStatement(node)) {
            return node;
          }

          if (!isSourceFile(node) && isObfsIgnoreNode(node, sourceFile)) {
            return node;
          }

          // module name in import / export like statement
          if ((isImportDeclaration(node) || isExportDeclaration(node)) && node.moduleSpecifier) {
            return node;
          }

          if (isImportEqualsDeclaration(node)) {
            return node;
          }

          if (isTypeAliasDeclaration(node)) {
            return node;
          }

          // TS18033: Only numeric enums can have computed members, but this expression has type 'string'. If
          // you do not need exhaustiveness checks, consider using an object literal instead.
          if (isEnumDeclaration(node)) {
            return node;
          }

          if (!isStringLiteralLike(node)) {
            return visitEachChild(node, stringVisitor, context);
          }

          if (isExpressionStatement(node.parent)) {
            return node;
          }

          if (stringOption.mSkipProperty && isElementAccessExpression(node.parent)) {
            return node;
          }

          if (stringOption.mReservedStrings && stringOption.mReservedStrings.includes(node.text)) {
            return node;
          }

          if (!helper.isTargetStr(node.text)) {
            return node;
          }

          if (!NodeUtils.isExtractableString(node)) {
            return visitEachChild(node, stringVisitor, context);
          }

          let prob: number = Math.random();
          if (prob > stringOption.mThreshold) {
            return node;
          }

          return helper.prepareReplaceStruct(node);
        }
      }
    }
  };

  const TRANSFORMER_ORDER: number = 8;
  export let transformerPlugin: TransformPlugin = {
    'name': 'Data Obfuscation',
    'order': (1 << TRANSFORMER_ORDER),
    'createTransformerFactory': createDataObfuscationFactory
  };
}

export = secharmony;
