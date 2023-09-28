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

function isInstanceofContext(tsIdentStart: ts.Node): boolean {
  return ts.isBinaryExpression(tsIdentStart.parent) &&
    tsIdentStart.parent.operatorToken.kind === ts.SyntaxKind.InstanceOfKeyword
}

function isNewExpressionContext(tsIdentStart: ts.Node): boolean {
  return ts.isNewExpression(tsIdentStart.parent) && tsIdentStart === tsIdentStart.parent.expression
}

function isQualifiedNameContext(tsIdentStart: ts.Node, tsIdentifier: ts.Identifier): boolean {
  // rightmost in AST is rightmost in qualified name chain
  return ts.isQualifiedName(tsIdentStart) && tsIdentifier !== tsIdentStart.right
}

function isPropertyAccessContext(tsIdentStart: ts.Node, tsIdentifier: ts.Identifier): boolean {
  // rightmost in AST is rightmost in qualified name chain
  return ts.isPropertyAccessExpression(tsIdentStart) && tsIdentifier !== tsIdentStart.name
}

function getQualifiedStart(ident: ts.Node): ts.Node {
  let qualifiedStart: ts.Node = ident;
  while (ts.isPropertyAccessExpression(qualifiedStart.parent) || ts.isQualifiedName(qualifiedStart.parent)) {
    qualifiedStart = qualifiedStart.parent;
  }
  return qualifiedStart;
}

function isEnumPropAccess(ident: ts.Identifier, tsSym: ts.Symbol, context: ts.Node): boolean {
  return ts.isElementAccessExpression(context) &&
    (context as ts.ElementAccessExpression).expression == ident &&
    !!(tsSym.flags & ts.SymbolFlags.Enum);
}

function isValidTypeNode(node: ts.TypeNode): boolean {
  return !ts.isTypeOfExpression(node);
}

export function identiferUseInValueContext(
  ident: ts.Identifier, tsSym: ts.Symbol
) {
  let qualifiedStart = getQualifiedStart(ident);
  let parent = qualifiedStart.parent;

  return !(
    // treat TypeQuery as valid because it's already forbidden (FaultID.TypeQuery)
    ts.isTypeNode(parent) && isValidTypeNode(parent) ||
    // If identifier is the right-most name of Property Access chain or Qualified name,
    // or it's a separate identifier expression, then identifier is being referenced as an value.
    isEnumPropAccess(ident, tsSym, parent) ||
    ts.isExpressionWithTypeArguments(parent) ||
    ts.isExportAssignment(parent) ||
    ts.isExportSpecifier(parent) ||
    ts.isMetaProperty(parent) ||
    ts.isImportClause(parent) ||
    ts.isClassLike(parent) ||
    ts.isInterfaceDeclaration(parent) ||
    ts.isModuleDeclaration(parent) ||
    ts.isEnumDeclaration(parent) ||
    ts.isNamespaceImport(parent) ||
    ts.isImportSpecifier(parent) ||
    isQualifiedNameContext(qualifiedStart, ident) ||
    isPropertyAccessContext(qualifiedStart, ident) ||
    isNewExpressionContext(qualifiedStart) ||
    isInstanceofContext(qualifiedStart) ||
    ts.isImportEqualsDeclaration(parent)
  );
}
