/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import * as ts from 'typescript';

export function scopeContainsThis(tsNode: ts.Node): boolean {
  let found = false;
  function visitNode(tsNode: ts.Node) {
    // Stop visiting child nodes if finished searching.
    if (found) {
      return;
    }
    if (tsNode.kind === ts.SyntaxKind.ThisKeyword) {
      found = true;
      return;
    }
    // Visit children nodes. Skip any local declaration that defines
    // its own scope as it needs to be checked separately.
    if (
      !ts.isClassDeclaration(tsNode) &&
      !ts.isClassExpression(tsNode) &&
      !ts.isModuleDeclaration(tsNode) &&
      !ts.isFunctionDeclaration(tsNode) &&
      !ts.isFunctionExpression(tsNode)
    )
      tsNode.forEachChild(visitNode);
  }
  visitNode(tsNode);
  return found;
}
  