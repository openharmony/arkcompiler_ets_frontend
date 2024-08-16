/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
  isStructDeclaration,
  setParentRecursive,
  visitEachChild,
  isConstructorDeclaration,
  isSourceFile,
  getOriginalNode
} from 'typescript';

import type {
  ClassElement,
  Node,
  SourceFile,
  TransformationContext,
  Transformer,
  TransformerFactory
} from 'typescript';

import type {TransformPlugin} from '../TransformPlugin';
import {TransformerOrder} from '../TransformPlugin';
import type {IOptions} from '../../configs/IOptions';
import {NodeUtils} from '../../utils/NodeUtils';
import {performancePrinter} from '../../ArkObfuscator';
import {EventList} from '../../utils/PrinterUtils';

namespace secharmony {
  export let transformerPlugin: TransformPlugin = {
    'name': 'VirtualConstructorTransformerFactory',
    'order': TransformerOrder.VIRTUAL_CONSTRUCTOR_TRANSFORMER,
    'createTransformerFactory': (option: IOptions) => virtualConstructorTransformerFactory,
  };
}

function virtualConstructorTransformerFactory(context: TransformationContext): Transformer<Node> {
  return (node: SourceFile) => virtualConstructorTransformer(node, context);
}

function virtualConstructorTransformer(node: SourceFile, context: TransformationContext): Node {
  if (!NodeUtils.isDETSFile(node)) {
    return node;
  }
  performancePrinter?.singleFilePrinter?.startEvent(EventList.VIRTUAL_CONSTRUCTOR_OBFUSCATION,
      performancePrinter.timeSumPrinter);
  let astWithoutVirtualConstructor = removeVirtualConstructor(node, context);
  let parentNodes = setParentRecursive(astWithoutVirtualConstructor, true);
  performancePrinter?.singleFilePrinter?.endEvent(EventList.VIRTUAL_CONSTRUCTOR_OBFUSCATION,
      performancePrinter.timeSumPrinter);
  return parentNodes;
}

function removeVirtualConstructor(node: Node, context: TransformationContext): Node {
  if (isStructDeclaration(node)) {
    const tempStructMembers: ClassElement[] = node.members.filter((member) => !isVirtualConstructor(member));
    const structMembersWithoutVirtualConstructor = factory.createNodeArray(tempStructMembers);

    return factory.updateStructDeclaration(node, node.modifiers, node.name, node.typeParameters, node.heritageClauses,
      structMembersWithoutVirtualConstructor);
  }
  return visitEachChild(node, (childNode) => removeVirtualConstructor(childNode, context), context);
}

function isVirtualConstructor(node: Node): boolean {
  const originalNode = getOriginalNode(node);
  //@ts-ignore
  return isConstructorDeclaration(originalNode) && originalNode.virtual;
}

export = secharmony;
