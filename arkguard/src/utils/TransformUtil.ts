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
  isStructDeclaration,
  SyntaxKind,
  visitEachChild
} from 'typescript';

import type {
  CommentRange,
  Identifier,
  Node,
  SourceFile,
  StructDeclaration,
  TransformationContext 
} from 'typescript';
import type { IOptions } from '../configs/IOptions';

export interface ReservedNameInfo {
  universalReservedArray: RegExp[]; // items contain wildcards
  specificReservedArray: string[]; // items do not contain wildcards
}

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

type IdentifiersAndStructs = {shadowIdentifiers: Identifier[], shadowStructs: StructDeclaration[]};

/**
 * collect exist identifiers in current source file
 * @param sourceFile
 * @param context
 */
export function collectIdentifiersAndStructs(sourceFile: SourceFile, context: TransformationContext): IdentifiersAndStructs {
  const identifiers: Identifier[] = [];
  const structs: StructDeclaration[] = [];

  let visit = (node: Node): Node => {
    if (isStructDeclaration(node)) {
      structs.push(node);
    }
    // @ts-ignore
    if (node.virtual) {
      return node;
    }
    if (!isIdentifier(node) || !node.parent) {
      return visitEachChild(node, visit, context);
    }

    identifiers.push(node);
    return node;
  };

  visit(sourceFile);
  return {shadowIdentifiers: identifiers, shadowStructs: structs};
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

/**
 * separate wildcards from specific items.
 */
export function separateUniversalReservedItem(originalArray: string[]): ReservedNameInfo {
  if (!originalArray) {
    throw new Error('Unable to handle the empty array.');
  }
  const reservedInfo: ReservedNameInfo = {
    universalReservedArray: [],
    specificReservedArray: []
  };

  originalArray.forEach(reservedItem => {
    if (containWildcards(reservedItem)) {
      const regexPattern = wildcardTransformer(reservedItem);
      const regexOperator = new RegExp(`^${regexPattern}$`);
      reservedInfo.universalReservedArray.push(regexOperator);
    } else {
      reservedInfo.specificReservedArray.push(reservedItem);
    }
  });
  return reservedInfo;
}

/**
 * check if the item contains '*', '?'.
 */
export function containWildcards(item: string): boolean {
  return /[\*\?]/.test(item);
}

/**
 * Convert specific characters into regular expressions.
 */
export function wildcardTransformer(wildcard: string, isPath?: boolean): string {
  // Add an escape character in front of special characters
  // special characters: '\', '^', '$', '.', '+', '|', '[', ']', '{', '}', '(', ')'
  let escapedItem = wildcard.replace(/[\\+^${}()|\[\]\.]/g, '\\$&');

  // isPath: containing '**', and '*', '?' can not be matched with '/'. 
  if (isPath) {
    // before: ../**/a/b/c*/?.ets
    // after: ../.*/a/b/c[^/]*/[^/].ets
    return escapedItem.replace(/\*\*/g, '.*').replace(/(?<!\.)\*/g, '[^/]*').replace(/\?/g, '[^/]');
  }
  // before: *a?
  // after: .*a.
  return escapedItem.replace(/\*/g, '.*').replace(/\?/g, '.');
}

/**
 * Determine whether the original name needs to be preserved.
 */
export function needToBeReserved(reservedSet: Set<string>, universalArray: RegExp[], originalName: string): boolean {
  return reservedSet.has(originalName) || isMatchWildcard(universalArray, originalName);
}

/**
 * Determine whether it can match the wildcard character in the array.
 */
export function isMatchWildcard(wildcardArray: RegExp[], item: string): boolean {
  for (const wildcard of wildcardArray) {
    if (wildcard.test(item)) {
      return true;
    }
  }
  return false;
}

/**
 * Separate parts of an array that contain wildcard characters.
 */
export function handleReservedConfig(config: IOptions, optionName: string, reservedListName: string,
  universalLisName: string, enableRemove?: string): void {
  const reservedConfig = config?.[optionName];
  let needSeparate: boolean = !!(reservedConfig?.[reservedListName]);
  if (enableRemove) {
    needSeparate &&= reservedConfig[enableRemove];
  }
  if (needSeparate) {
    // separate items which contain wildcards from others
    const reservedInfo: ReservedNameInfo = separateUniversalReservedItem(reservedConfig[reservedListName]);
    reservedConfig[reservedListName] = reservedInfo.specificReservedArray;
    reservedConfig[universalLisName] = reservedInfo.universalReservedArray;
  }
}
