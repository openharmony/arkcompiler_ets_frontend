/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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
import { AutofixInfo } from './AutofixInfo';
import { FaultID } from './Problems';
import { isAssignmentOperator } from './Utils';

export const AUTOFIX_ALL: AutofixInfo = {
  problemID: '', start: -1, end: -1
}

// Some fixes are potentially risky and may break source code if fixes
// are applied separately.
// Temporary solution is to disable all risky autofixes, until the
// algorithm is improved to guarantee that fixes can be applied
// safely and won't break program code.
const UNSAFE_FIXES: FaultID[] = [ FaultID.LiteralAsPropertyName, FaultID.PropertyAccessByIndex ];

export interface Autofix {
  replacementText: string;
  start: number;
  end: number;
}

export class AutofixInfoSet {
  private autofixInfo: AutofixInfo[];

  constructor(autofixInfo: AutofixInfo[] | undefined) {
    this.autofixInfo = autofixInfo ? autofixInfo : [];
  }

  public shouldAutofix(node: ts.Node, faultID: FaultID): boolean {
    if (UNSAFE_FIXES.includes(faultID)) return false;
    if (this.autofixInfo.length === 0) return false;
    if (this.autofixInfo.length === 1 && this.autofixInfo[0] == AUTOFIX_ALL) return true;
    return this.autofixInfo.findIndex(
      value => value.start === node.getStart() && value.end === node.getEnd() && value.problemID === FaultID[faultID]
    ) !== -1;
  }
}

export function fixLiteralAsPropertyName(node: ts.Node): Autofix[] | undefined {
  if (ts.isPropertyDeclaration(node) || ts.isPropertyAssignment(node)) {
    let propName = (node as (ts.PropertyDeclaration | ts.PropertyAssignment)).name;
    let identName = propertyName2IdentifierName(propName);
    if (identName) 
      return [{ replacementText: identName, start: propName.getStart(), end: propName.getEnd() }];
  }
  return undefined;
}

export function fixPropertyAccessByIndex(node: ts.Node): Autofix[] | undefined {
  if (ts.isElementAccessExpression(node)) {
    let elemAccess = node as ts.ElementAccessExpression;
    let identifierName = indexExpr2IdentifierName(elemAccess.argumentExpression);
    if (identifierName) 
      return [{ 
        replacementText: elemAccess.expression.getText() + '.' + identifierName, 
        start: elemAccess.getStart(), end: elemAccess.getEnd() 
      }];
  }
  return undefined;
}

export function fixFunctionExpression(funcExpr: ts.FunctionExpression, 
  params: ts.NodeArray<ts.ParameterDeclaration> = funcExpr.parameters, 
  retType: ts.TypeNode | undefined = funcExpr.type,
  modifiers: readonly ts.Modifier[] | undefined): Autofix {
  let arrowFunc: ts.Expression = ts.factory.createArrowFunction(
    modifiers, undefined, params, retType, ts.factory.createToken(ts.SyntaxKind.EqualsGreaterThanToken), 
    funcExpr.body
  );
  if (needsParentheses(funcExpr)) {
    arrowFunc = ts.factory.createParenthesizedExpression(arrowFunc);
  }
  let text = printer.printNode(ts.EmitHint.Unspecified, arrowFunc, funcExpr.getSourceFile());
  return { start: funcExpr.getStart(), end: funcExpr.getEnd(), replacementText: text };
}

export function fixReturnType(funcLikeDecl: ts.FunctionLikeDeclaration, typeNode: ts.TypeNode): Autofix {
  let text = ': ' + printer.printNode(ts.EmitHint.Unspecified, typeNode, funcLikeDecl.getSourceFile());
  let pos = getReturnTypePosition(funcLikeDecl);
  return { start: pos, end: pos, replacementText: text };
}

export function dropTypeOnVarDecl(varDecl: ts.VariableDeclaration): Autofix {
  let newVarDecl = ts.factory.createVariableDeclaration(varDecl.name, undefined, undefined, undefined);
  let text = printer.printNode(ts.EmitHint.Unspecified, newVarDecl, varDecl.getSourceFile());
  return { start: varDecl.getStart(), end: varDecl.getEnd(), replacementText: text};
}

export function dropTypeOnlyFlag(
  impExpNode: ts.ImportClause | ts.ExportDeclaration
): Autofix {
  let text: string;
  if (ts.isImportClause(impExpNode)) {
    let newImportClause = ts.factory.createImportClause(false, impExpNode.name, impExpNode.namedBindings);
    text = printer.printNode(ts.EmitHint.Unspecified, newImportClause, impExpNode.getSourceFile());
  }
  else {
    let newExportDecl = ts.factory.createExportDeclaration(undefined, impExpNode.modifiers, false,
      impExpNode.exportClause, impExpNode.moduleSpecifier);
    text = printer.printNode(ts.EmitHint.Unspecified, newExportDecl, impExpNode.getSourceFile());
  }
  return { start: impExpNode.getStart(), end: impExpNode.getEnd(), replacementText: text };
}

export function fixDefaultImport(importClause: ts.ImportClause, 
  defaultSpec: ts.ImportSpecifier, nonDefaultSpecs: ts.ImportSpecifier[]): Autofix {
  let nameBindings = nonDefaultSpecs.length > 0 ? ts.factory.createNamedImports(nonDefaultSpecs) : undefined;
  let newImportClause = ts.factory.createImportClause(importClause.isTypeOnly, defaultSpec.name, nameBindings);
  let text = printer.printNode(ts.EmitHint.Unspecified, newImportClause, importClause.getSourceFile());
  return { start: importClause.getStart(), end: importClause.getEnd(), replacementText: text };
}

export function fixTypeAssertion(typeAssertion: ts.TypeAssertion): Autofix {
  const asExpr = ts.factory.createAsExpression(typeAssertion.expression, typeAssertion.type);
  let text = printer.printNode(ts.EmitHint.Unspecified, asExpr, typeAssertion.getSourceFile());
  return { start: typeAssertion.getStart(), end: typeAssertion.getEnd(), replacementText: text };
}

const printer: ts.Printer = ts.createPrinter();

function numericLiteral2IdentifierName(numeric: ts.NumericLiteral) {
  return '__' + numeric.getText();
}

function stringLiteral2IdentifierName(str: ts.StringLiteral) {
  let text = (str as ts.StringLiteral).getText();
  return text.substring(1, text.length-1); // cut out starting and ending quoters.
}

function propertyName2IdentifierName(name: ts.PropertyName): string {
  if (name.kind === ts.SyntaxKind.NumericLiteral) 
    return numericLiteral2IdentifierName(name as ts.NumericLiteral);

  if (name.kind === ts.SyntaxKind.StringLiteral) 
    return stringLiteral2IdentifierName(name as ts.StringLiteral);
        
  return '';
}

function indexExpr2IdentifierName(index: ts.Expression) {
  if (index.kind === ts.SyntaxKind.NumericLiteral) 
    return numericLiteral2IdentifierName(index as ts.NumericLiteral);

  if (index.kind === ts.SyntaxKind.StringLiteral) 
    return stringLiteral2IdentifierName(index as ts.StringLiteral);
    
  return '';
}

function getReturnTypePosition(funcLikeDecl: ts.FunctionLikeDeclaration): number {
  if (funcLikeDecl.body) {
    // Find position of the first node or token that follows parameters.
    // After that, iterate over child nodes in reverse order, until found
    // first closing parenthesis.
    let postParametersPosition = ts.isArrowFunction(funcLikeDecl)
      ? funcLikeDecl.equalsGreaterThanToken.getStart()
      : funcLikeDecl.body.getStart();
    
    const children = funcLikeDecl.getChildren();
    for (let i = children.length - 1; i >= 0; i--) {
      const child = children[i];
      if (child.kind === ts.SyntaxKind.CloseParenToken && child.getEnd() < postParametersPosition)
        return child.getEnd();
    }
  }

  // Shouldn't get here.
  return -1;
}

function needsParentheses(node: ts.FunctionExpression): boolean {
  const parent = node.parent;
  return ts.isPrefixUnaryExpression(parent) || ts.isPostfixUnaryExpression(parent) ||
    ts.isPropertyAccessExpression(parent) || ts.isElementAccessExpression(parent) ||
    ts.isTypeOfExpression(parent) || ts.isVoidExpression(parent) || ts.isAwaitExpression(parent) ||
    (ts.isCallExpression(parent) && node === parent.expression) ||
    (ts.isBinaryExpression(parent) && !isAssignmentOperator(parent.operatorToken));
}