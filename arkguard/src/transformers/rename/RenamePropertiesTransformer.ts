/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
  isComputedPropertyName,
  isConstructorDeclaration,
  isElementAccessExpression,
  isIdentifier,
  isNumericLiteral,
  isPrivateIdentifier,
  isStringLiteralLike,
  setParentRecursive,
  visitEachChild,
  isSourceFile,
  isIndexedAccessTypeNode,
  isLiteralTypeNode,
  isUnionTypeNode,
} from 'typescript';

import type {
  ComputedPropertyName,
  Expression,
  Identifier,
  Node,
  TransformationContext,
  Transformer,
  TransformerFactory,
  ClassDeclaration,
  ClassExpression,
  StructDeclaration,
  PropertyName,
  StringLiteral,
  LiteralTypeNode,
  TypeNode
} from 'typescript';

import type {IOptions} from '../../configs/IOptions';
import type { INameObfuscationOption } from '../../configs/INameObfuscationOption';
import type {INameGenerator, NameGeneratorOptions} from '../../generator/INameGenerator';
import {getNameGenerator, NameGeneratorType} from '../../generator/NameFactory';
import type {TransformPlugin} from '../TransformPlugin';
import {TransformerOrder} from '../TransformPlugin';
import {NodeUtils} from '../../utils/NodeUtils';
import { ArkObfuscator, performancePrinter } from '../../ArkObfuscator';
import { EventList, endSingleFileEvent, startSingleFileEvent } from '../../utils/PrinterUtils';
import {
  isInPropertyWhitelist,
  isReservedProperty,
  needToRecordProperty
} from '../../utils/TransformUtil';
import {
  classInfoInMemberMethodCache,
  nameCache
} from './RenameIdentifierTransformer';
import { UpdateMemberMethodName } from '../../utils/NameCacheUtil';
import { PropCollections, UnobfuscationCollections } from '../../utils/CommonCollections';

namespace secharmony {
  /**
   * Rename Properties Transformer
   *
   * @param option obfuscation options
   */
  const createRenamePropertiesFactory = function (option: IOptions): TransformerFactory<Node> {
    let profile: INameObfuscationOption | undefined = option?.mNameObfuscation;

    if (!profile || !profile.mEnable || !profile.mRenameProperties) {
      return null;
    }

    return renamePropertiesFactory;

    function renamePropertiesFactory(context: TransformationContext): Transformer<Node> {
      let options: NameGeneratorOptions = {};
      let generator: INameGenerator = getNameGenerator(profile.mNameGeneratorType, options);

      return renamePropertiesTransformer;

      function renamePropertiesTransformer(node: Node): Node {
        if (isSourceFile(node) && ArkObfuscator.isKeptCurrentFile) {
          return node;
        }

        startSingleFileEvent(EventList.PROPERTY_OBFUSCATION, performancePrinter.timeSumPrinter);
        let ret: Node = renameProperties(node);
        UpdateMemberMethodName(nameCache, PropCollections.globalMangledTable, classInfoInMemberMethodCache);
        let parentNodes = setParentRecursive(ret, true);
        endSingleFileEvent(EventList.PROPERTY_OBFUSCATION, performancePrinter.timeSumPrinter);
        return parentNodes;
      }

      function renameProperties(node: Node): Node {
        if (!NodeUtils.isPropertyNode(node)) {
          return visitEachChild(node, renameProperties, context);
        }

        if (isElementAccessExpression(node.parent)) {
          return renameElementAccessProperty(node);
        }

        if (isIndexedAccessTypeNode(node.parent)) {
          return renameIndexedAccessProperty(node);
        }

        if (isComputedPropertyName(node)) {
          return renameComputedProperty(node);
        }

        return renameProperty(node, false);
      }

      function renameElementAccessProperty(node: Node): Node {
        if (isStringLiteralLike(node)) {
          return renameProperty(node, false);
        }
        return visitEachChild(node, renameProperties, context);
      }

      function renameIndexedAccessProperty(node: Node): Node {
        if (NodeUtils.isStringLiteralTypeNode(node)) {
          let prop = renameProperty((node as LiteralTypeNode).literal, false);
          if (prop !== (node as LiteralTypeNode).literal) {
            return factory.createLiteralTypeNode(prop as StringLiteral);
          }
          return visitEachChild(node, renameProperties, context);
        }

        if (!isUnionTypeNode(node)) {
          return visitEachChild(node, renameProperties, context);
        }

        let isChanged: boolean = false;
        const elemTypes = node.types.map((elemType) => {
          if (!elemType) {
            return elemType;
          }
          if (NodeUtils.isStringLiteralTypeNode(elemType)) {
            const prop = renameProperty((elemType as LiteralTypeNode).literal, false);
            if (prop !== (elemType as LiteralTypeNode).literal) {
              isChanged = true;
              return factory.createLiteralTypeNode(prop as StringLiteral);
            }
          }
          return elemType;
        });
        if (isChanged) {
          return factory.createUnionTypeNode(elemTypes);
        }
        return visitEachChild(node, renameProperties, context);
      }

      function renameComputedProperty(node: ComputedPropertyName): ComputedPropertyName {
        if (isStringLiteralLike(node.expression) || isNumericLiteral(node.expression)) {
          let prop: Node = renameProperty(node.expression, true);
          if (prop !== node.expression) {
            return factory.createComputedPropertyName(prop as Expression);
          }
        }

        if (isIdentifier(node.expression)) {
          return node;
        }

        return visitEachChild(node, renameProperties, context);
      }

      function renameProperty(node: Node, computeName: boolean): Node {
        if (!isStringLiteralLike(node) && !isIdentifier(node) && !isPrivateIdentifier(node) && !isNumericLiteral(node)) {
          return visitEachChild(node, renameProperties, context);
        }

        if (isStringLiteralLike(node) && profile?.mKeepStringProperty) {
          if (UnobfuscationCollections.printKeptName) {
            needToRecordProperty(node.text, UnobfuscationCollections.unobfuscatedPropMap);
          }
          return node;
        }

        let original: string = node.text;
        if (isInPropertyWhitelist(original, UnobfuscationCollections.unobfuscatedPropMap)) {
          return node;
        }

        let mangledName: string = getPropertyName(original);

        if (isStringLiteralLike(node)) {
          return factory.createStringLiteral(mangledName);
        }

        /**
         * source demo:
         * class A {
         *   123 = 1; // it is NumericLiteral
         *   [456] = 2; // it is NumericLiteral within ComputedPropertyName
         * }
         * obfuscation result:
         * class A {
         *   a = 1;
         *   ['b'] = 2;
         * }
         */
        if (isNumericLiteral(node)) {
          return computeName ? factory.createStringLiteral(mangledName) : factory.createIdentifier(mangledName);
        }

        if (isIdentifier(node) || isNumericLiteral(node)) {
          return factory.createIdentifier(mangledName);
        }

        return factory.createPrivateIdentifier('#' + mangledName);
      }

      function getPropertyName(original: string): string {
        const historyName: string = PropCollections.historyMangledTable?.get(original);
        let mangledName: string = historyName ? historyName : PropCollections.globalMangledTable.get(original);
        while (!mangledName) {
          let tmpName = generator.getName();
          if (isReservedProperty(tmpName) ||
            tmpName === original) {
            continue;
          }

          if (PropCollections.newlyOccupiedMangledProps.has(tmpName) || PropCollections.mangledPropsInNameCache.has(tmpName)) {
            continue;
          }

          mangledName = tmpName;
        }
        PropCollections.globalMangledTable.set(original, mangledName);
        PropCollections.newlyOccupiedMangledProps.add(mangledName);
        return mangledName;
      }
    }
  };

  export let transformerPlugin: TransformPlugin = {
    'name': 'renamePropertiesPlugin',
    'order': TransformerOrder.RENAME_PROPERTIES_TRANSFORMER,
    'createTransformerFactory': createRenamePropertiesFactory
  };
}

export = secharmony;
