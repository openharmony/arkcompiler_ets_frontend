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
  isBindingElement,
  isObjectBindingPattern,
  isShorthandPropertyAssignment,
  isSourceFile,
  isStructDeclaration,
  setParentRecursive,
  visitEachChild,
  isConstructorDeclaration
} from 'typescript';

import type {
  BindingElement,
  ClassElement,
  Expression,
  Identifier,
  Node,
  SourceFile,
  StructDeclaration,
  TransformationContext,
  Transformer,
  TransformerFactory
} from 'typescript';

import type {INameObfuscationOption} from '../../configs/INameObfuscationOption';
import type {TransformPlugin} from '../TransformPlugin';
import {TransformerOrder} from '../TransformPlugin';
import type {IOptions} from '../../configs/IOptions';
import {NodeUtils} from '../../utils/NodeUtils';
import {ArkObfuscator, performancePrinter} from '../../ArkObfuscator';
import { EventList, endSingleFileEvent, startSingleFileEvent } from '../../utils/PrinterUtils';
import { MemoryDottingDefine } from '../../utils/MemoryDottingDefine';

namespace secharmony {
  const createShorthandPropertyTransformerFactory = function (option: IOptions): TransformerFactory<Node> | null {
    let profile: INameObfuscationOption = option.mNameObfuscation;
    if (!profile || !profile.mEnable) {
      return null;
    }

    return shorthandPropertyTransformFactory;

    function shorthandPropertyTransformFactory(context: TransformationContext): Transformer<Node> {
      return shorthandPropertyTransformer;

      function shorthandPropertyTransformer(node: Node): Node {
        if (isSourceFile(node) && ArkObfuscator.isKeptCurrentFile) {
          return node;
        }

        const recordInfo = ArkObfuscator.recordStage(MemoryDottingDefine.SHORTHAND_OBFUSCATION);
        startSingleFileEvent(EventList.SHORT_HAND_OBFUSCATION, performancePrinter.timeSumPrinter);
        let ret = transformShortHandProperty(node);
        let parentNodes = setParentRecursive(ret, true);
        endSingleFileEvent(EventList.SHORT_HAND_OBFUSCATION, performancePrinter.timeSumPrinter);
        ArkObfuscator.stopRecordStage(recordInfo);
        return parentNodes;
      }

      function transformShortHandProperty(node: Node): Node {
        /**
         * example:
         * `let name1 = 'hello';`
         * `let info = {name1};`
         * obfuscated example:
         * `let name1 = 'hello';`;
         * `let info = {name1: name1};`
         */
        if (isShorthandPropertyAssignment((node))) {
          let initializer = node.objectAssignmentInitializer;
          let expression: Expression = node.name;
          if (initializer) {
            expression = factory.createBinaryExpression(node.name, node.equalsToken, initializer);
          }

          let identifier = factory.createIdentifier(node.name.text);
          return factory.createPropertyAssignment(identifier, expression);
        }

        /**
         * exclude grammar instance: let [name2, age2] = ['akira', 22];
         * 
         * grammar: {name1, ...rest}= {'name1': 'akira', age : 22};
         * an alias will be created for name1.
         * no alias will be created for rest.
         * 
         * include grammars:
         * orinal ObjectBinding():
         * const { name3, age3 } = foo3();
         * const { name4, addr4: { contry, place} } = foo4();
         * obfuscated ObjectBinding:
         * `const { name3: name3, age3: age3 } = foo3();`
         * `const { name4: name4, addr4: { contry: contry, place: place}  } = { name4: 4, addr4: { contry:5, place:6} };`
         */
        if (isElementsInObjectBindingPattern(node) && !node.propertyName && !node.dotDotDotToken) {
          return factory.createBindingElement(node.dotDotDotToken, factory.createIdentifier((node.name as Identifier).text),
            node.name, node.initializer);
        }

        return visitEachChild(node, transformShortHandProperty, context);
      }

      function isElementsInObjectBindingPattern(node: Node): node is BindingElement {
        return node.parent && isObjectBindingPattern(node.parent) && isBindingElement(node);
      }
    }
  };

  export let transformerPlugin: TransformPlugin = {
    'name': 'ShortHandPropertyTransformer',
    'order': TransformerOrder.SHORTHAND_PROPERTY_TRANSFORMER,
    'createTransformerFactory': createShorthandPropertyTransformerFactory,
  };
}

export = secharmony;
