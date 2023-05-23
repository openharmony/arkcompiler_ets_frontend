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
  forEachChild,
  isClassDeclaration,
  isComputedPropertyName,
  isConstructorDeclaration,
  isElementAccessExpression,
  isEnumMember,
  isIdentifier,
  isNumericLiteral,
  isPrivateIdentifier,
  isStringLiteralLike,
  isTypeNode,
  setParentRecursive,
  visitEachChild
} from 'typescript';

import type {
  ComputedPropertyName,
  EnumMember,
  Expression,
  Identifier,
  Node,
  TransformationContext,
  Transformer,
  TransformerFactory
} from 'typescript';

import type {IOptions} from '../../configs/IOptions';
import type {INameObfuscationOption} from '../../configs/INameObfuscationOption';
import type {INameGenerator, NameGeneratorOptions} from '../../generator/INameGenerator';
import {getNameGenerator, NameGeneratorType} from '../../generator/NameFactory';
import type {TransformPlugin} from '../TransformPlugin';
import {NodeUtils} from '../../utils/NodeUtils';
import { getClassProperties, isViewPUBasedClass } from '../../utils/OhsUtil';

namespace secharmony {
  /**
   * global mangled properties table used by all files in a project
   */
  export let globalMangledTable: Map<string, string> = undefined;

  // used for property cache
  export let historyMangledTable: Map<string, string> = undefined;

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
      if (profile.mNameGeneratorType === NameGeneratorType.HEX) {
        options.hexWithPrefixSuffix = true;
      }

      let generator: INameGenerator = getNameGenerator(profile.mNameGeneratorType, options);

      let reservedProperties: string[] = profile?.mReservedProperties ?? [];
      let reservedNamesInEnum: string[] = [];

      let currentConstructorParams: Set<string> = new Set<string>();

      return renamePropertiesTransformer;

      function renamePropertiesTransformer(node: Node): Node {
        collectReservedNames(node);
        if (globalMangledTable === undefined) {
          globalMangledTable = new Map<string, string>();
        }

        let ret: Node = renameProperties(node);
        return setParentRecursive(ret, true);
      }

      function renameProperties(node: Node): Node {
        if (isConstructorDeclaration(node)) {
          currentConstructorParams.clear();
        }

        if (NodeUtils.isClassPropertyInConstructorParams(node)) {
          currentConstructorParams.add((node as Identifier).escapedText.toString());
          return renameProperty(node, false);
        }

        if (NodeUtils.isClassPropertyInConstructorBody(node, currentConstructorParams)) {
          if (currentConstructorParams.has((node as Identifier).escapedText.toString())) {
            return renameProperty(node, false);
          }
        }

        if (!NodeUtils.isPropertyNode(node)) {
          return visitEachChild(node, renameProperties, context);
        }

        if (isElementAccessExpression(node.parent)) {
          return renameElementAccessProperty(node);
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

        let original: string = node.text;
        if (reservedProperties.includes(original)) {
          return node;
        }

        let mangledName: string = getPropertyName(original);

        if (isStringLiteralLike(node)) {
          return factory.createStringLiteral(mangledName);
        }

        if (isNumericLiteral(node)) {
          return computeName ? factory.createStringLiteral(mangledName) : factory.createIdentifier(mangledName);

        }

        if (isIdentifier(node) || isNumericLiteral(node)) {
          return factory.createIdentifier(mangledName);
        }

        return factory.createPrivateIdentifier('#' + mangledName);
      }

      function getPropertyName(original: string): string {
        const historyName: string = historyMangledTable?.get(original);
        let mangledName: string = historyName ? historyName : globalMangledTable.get(original);

        while (!mangledName) {
          mangledName = generator.getName();
          if (mangledName === original) {
            mangledName = null;
            continue;
          }

          if (reservedProperties.includes(mangledName)) {
            mangledName = null;
            continue;
          }

          let reserved: string[] = [...globalMangledTable.values()];
          if (historyMangledTable) {
            reserved = [...reserved, ...historyMangledTable.values()];
          }

          if (reserved.includes(mangledName)) {
            mangledName = null;
            continue;
          }

          if (reservedNamesInEnum.includes(mangledName)) {
            mangledName = null;
          }
        }
        globalMangledTable.set(original, mangledName);
        return mangledName;
      }

      // enum syntax has special scenarios
      function collectReservedNames(node: Node): void {
        if (!isEnumMember(node) && !isClassDeclaration(node)) {
          forEachChild(node, collectReservedNames);
        }

        // collect viewPU class properties
        if (isClassDeclaration(node)) {
          if (!isViewPUBasedClass(node)) {
            return;
          }
          const properties = getClassProperties(node);
          properties.forEach((property) => {
            reservedProperties.push(property);
          });
          return;
        }

        // collect enum properties
        let initial: Expression = (node as EnumMember).initializer;
        let visit = function (child: Node): void {
          if (!isIdentifier(child)) {
            return;
          }

          if (NodeUtils.isPropertyNode(child)) {
            return;
          }

          if (isTypeNode(child)) {
            return;
          }
          reservedNamesInEnum.push(child.text);
        };

        forEachChild(initial, visit);
      }
    }
  };

  const TRANSFORMER_ORDER: number = 6;
  export let transformerPlugin: TransformPlugin = {
    'name': 'renamePropertiesPlugin',
    'order': (1 << TRANSFORMER_ORDER),
    'createTransformerFactory': createRenamePropertiesFactory
  };
}

export = secharmony;
