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
  forEachChild,
  getLeadingCommentRangesOfNode,
  isCallExpression,
  isExpressionStatement,
  isIdentifier,
  SyntaxKind,
  visitEachChild
} from 'typescript';

import type {
  CommentRange,
  Identifier,
  Node,
  SourceFile,
  TransformationContext 
} from 'typescript';

/**
 * collect exist identifier names in current source file
 * @param sourceFile
 */
export function collectExistNames(sourceFile: SourceFile): Set<string> {
  const identifiers: Set<string> = new Set<string>();

  let visit = (node: Node): void => {
    if (isIdentifier(node)) {
      identifiers.add(node.text);
    }

    forEachChild(node, visit);
  };

  forEachChild(sourceFile, visit);
  return identifiers;
}

/**
 * collect exist identifiers in current source file
 * @param sourceFile
 * @param context
 */
export function collectIdentifiers(sourceFile: SourceFile, context: TransformationContext): Identifier[] {
  const identifiers: Identifier[] = [];

  let visit = (node: Node): Node => {
    if (!isIdentifier(node) || !node.parent) {
      return visitEachChild(node, visit, context);
    }

    identifiers.push(node);
    return node;
  };

  visit(sourceFile);
  return identifiers;
}

export enum OhPackType {
  NONE,
  JS_BUNDLE,
  ES_MODULE
}

export function isCommentedNode(node: Node, sourceFile: SourceFile): boolean {
  const ranges: CommentRange[] = getLeadingCommentRangesOfNode(node, sourceFile);
  return ranges !== undefined;
}

export function isSuperCallStatement(node: Node): boolean {
  return isExpressionStatement(node) &&
    isCallExpression(node.expression) &&
    node.expression.expression.kind === SyntaxKind.SuperKeyword;
}
