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
  isComputedPropertyName,
  isConstructorDeclaration,
  isElementAccessExpression,
  isEnumMember,
  isIdentifier,
  isClassDeclaration,
  isNumericLiteral,
  isPrivateIdentifier,
  isStringLiteralLike,
  isTypeNode,
  setParentRecursive,
  visitEachChild,
  isStringLiteral
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
  PropertyName
} from 'typescript';

import type {IOptions} from '../../configs/IOptions';
import type {INameObfuscationOption} from '../../configs/INameObfuscationOption';
import type {INameGenerator, NameGeneratorOptions} from '../../generator/INameGenerator';
import {getNameGenerator, NameGeneratorType} from '../../generator/NameFactory';
import type {TransformPlugin} from '../TransformPlugin';
import {NodeUtils} from '../../utils/NodeUtils';
import {collectPropertyNamesAndStrings, isViewPUBasedClass} from '../../utils/OhsUtil';

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

      let tmpReservedProps: string[] = profile?.mReservedProperties ?? [];
      let reservedProperties: Set<string> = new Set<string>(tmpReservedProps);

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
        if (reservedProperties.has(original)) {
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
        if (reservedProperties.has(original)) {
          return original;
        }

        const historyName: string = historyMangledTable?.get(original);
        let mangledName: string = historyName ? historyName : globalMangledTable.get(original);

        while (!mangledName) {
          mangledName = generator.getName();
          if (mangledName === original || reservedProperties.has(mangledName)) {
            mangledName = null;
            continue;
          }

          let reserved: string[] = [...globalMangledTable.values()];
          if (historyMangledTable) {
            reserved = [...reserved, ...historyMangledTable.values()];
          }

          if (reserved.includes(mangledName)) {
            mangledName = null;
          }
        }
        globalMangledTable.set(original, mangledName);
        return mangledName;
      }

      function visitEnumInitializer(childNode: Node): void {
        if (!isIdentifier(childNode)) {
          forEachChild(childNode, visitEnumInitializer);
          return;
        }

        if (NodeUtils.isPropertyNode(childNode)) {
          return;
        }

        if (isTypeNode(childNode)) {
          return;
        }

        reservedProperties.add(childNode.text);
      }

      // enum syntax has special scenarios
      function collectReservedNames(node: Node): void {
        // collect ViewPU class properties
        if (isClassDeclaration(node) && isViewPUBasedClass(node)) {
          getViewPUClassProperties(node, reservedProperties);
          return;
        }

        // collect reserved name of enum
        // example: enum H {A, B = A + 1}, enum H = {A, B= 1 + (A + 1)}; A is reserved
        if (isEnumMember(node) && node.initializer) {
          // collect enum properties
          node.initializer.forEachChild(visitEnumInitializer);
          return;
        }

        forEachChild(node, collectReservedNames);
      }

      function getViewPUClassProperties(classNode: ClassDeclaration | ClassExpression | StructDeclaration, propertySet: Set<string>): void {
        if (!classNode || !classNode.members) {
          return;
        }

        classNode.members.forEach((member) => {
          const memberName: PropertyName = member.name;
          if (!member || !memberName) {
            return;
          }
          collectPropertyNamesAndStrings(memberName, propertySet);
        });
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
