/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

function scopeContainsThisVisitor(tsNode: ts.Node): boolean {
  if (tsNode.kind === ts.SyntaxKind.ThisKeyword) {
    return true;
  }

  /*
   * Visit children nodes. Skip any local declaration that defines
   * its own scope as it needs to be checked separately.
   */
  const isClassLike = ts.isClassDeclaration(tsNode) || ts.isClassExpression(tsNode);
  const isFunctionLike = ts.isFunctionDeclaration(tsNode) || ts.isFunctionExpression(tsNode);
  const isModuleDecl = ts.isModuleDeclaration(tsNode);
  if (isClassLike || isFunctionLike || isModuleDecl) {
    return false;
  }

  for (const child of tsNode.getChildren()) {
    if (scopeContainsThisVisitor(child)) {
      return true;
    }
  }

  return false;
}

export function scopeContainsThis(tsNode: ts.Expression | ts.Block): boolean {
  return scopeContainsThisVisitor(tsNode);
}
