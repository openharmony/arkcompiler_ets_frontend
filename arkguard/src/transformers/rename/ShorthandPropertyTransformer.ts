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
  setParentRecursive,
  visitEachChild
} from 'typescript';

import type {
  BindingElement,
  Identifier,
  Node,
  TransformationContext,
  Transformer,
  TransformerFactory
} from 'typescript';

import type {INameObfuscationOption} from '../../configs/INameObfuscationOption';
import type {TransformPlugin} from '../TransformPlugin';
import type {IOptions} from '../../configs/IOptions';
import {NodeUtils} from '../../utils/NodeUtils';

namespace secharmony {
  const createShorthandPropertyTransformerFactory = function (option: IOptions): TransformerFactory<Node> {
    let profile: INameObfuscationOption = option.mNameObfuscation;
    if (!profile || !profile.mEnable) {
      return null;
    }

    return shorthandPropertyTransformFactory;

    function shorthandPropertyTransformFactory(context: TransformationContext): Transformer<Node> {
      return shorthandPropertyTransformer;

      function shorthandPropertyTransformer(node: Node): Node {
        return setParentRecursive(transformShortHandProperty(node), true);
      }

      function transformShortHandProperty(node: Node): Node {
        /**
         * ShortHandProperty example:
         * `let name = 'hello;`
         * `let info = {name};`
         */
        if (isShorthandPropertyAssignment((node))) {
          // update parent
          return factory.createPropertyAssignment(factory.createIdentifier(node.name.text), node.name);
        }
        /**
         * orinal ObjectBinding:
         * `const { x, y } = { x: 1, y: 2 };`
         * `const { x: a, y: b} = { x, y };`
         * obfuscated ObjectBinding:
         * `const { x: a, y: b } = { x: 1, y: 2 };`
         * `const { x: c, y: d } = { x: a, y: b };`
         */
        if (isObjectBindingPattern(node) && NodeUtils.isObjectBindingPatternAssignment(node)) {
          return node;
        }

        /**
         * exclude, eg {name, ...rest}= {'name': 'akira', age : 22}
         * exclude, eg let [name, age] = ['akira', 22];
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

  const TRANSFORMER_ORDER: number = 0;
  export let transformerPlugin: TransformPlugin = {
    'name': 'ShortHandPropertyTransformer',
    'order': (1 << TRANSFORMER_ORDER),
    'createTransformerFactory': createShorthandPropertyTransformerFactory,
  };
}

export = secharmony;
