/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
import type { AutofixInfo } from './autofixes/AutofixInfo';
import { FaultID } from './Problems';
import { isAssignmentOperator } from './utils/functions/isAssignmentOperator';
import { TsUtils } from './utils/TsUtils';

export const AUTOFIX_ALL: AutofixInfo = {
  problemID: '',
  start: -1,
  end: -1
};

/*
 * Some fixes are potentially risky and may break source code if fixes
 * are applied separately.
 * Temporary solution is to disable all risky autofixes, until the
 * algorithm is improved to guarantee that fixes can be applied
 * safely and won't break program code.
 */
const UNSAFE_FIXES: FaultID[] = [];

export interface Autofix {
  replacementText: string;
  start: number;
  end: number;
}

export class AutofixInfoSet {
  private readonly autofixInfo: AutofixInfo[];

  constructor(autofixInfo: AutofixInfo[] | undefined) {
    this.autofixInfo = autofixInfo ? autofixInfo : [];
  }

  shouldAutofix(node: ts.Node, faultID: FaultID): boolean {
    if (UNSAFE_FIXES.includes(faultID)) {
      return false;
    }
    if (this.autofixInfo.length === 0) {
      return false;
    }
    if (this.autofixInfo.length === 1 && this.autofixInfo[0] === AUTOFIX_ALL) {
      return true;
    }
    return (
      this.autofixInfo.findIndex((value) => {
        return value.start === node.getStart() && value.end === node.getEnd() && value.problemID === FaultID[faultID];
      }) !== -1
    );
  }
}

export function fixLiteralAsPropertyName(node: ts.Node): Autofix[] | undefined {
  if (ts.isPropertyDeclaration(node) || ts.isPropertyAssignment(node)) {
    const propName = node.name;
    const identName = propertyName2IdentifierName(propName);
    if (identName) {
      return [{ replacementText: identName, start: propName.getStart(), end: propName.getEnd() }];
    }
  }
  return undefined;
}

export function fixPropertyAccessByIndex(node: ts.Node): Autofix[] | undefined {
  if (ts.isElementAccessExpression(node)) {
    const elemAccess = node;
    const identifierName = indexExpr2IdentifierName(elemAccess.argumentExpression);
    if (identifierName) {
      return [
        {
          replacementText: elemAccess.expression.getText() + '.' + identifierName,
          start: elemAccess.getStart(),
          end: elemAccess.getEnd()
        }
      ];
    }
  }
  return undefined;
}

export function fixFunctionExpression(
  funcExpr: ts.FunctionExpression,
  params: ts.NodeArray<ts.ParameterDeclaration> = funcExpr.parameters,
  typeParams: ts.NodeArray<ts.TypeParameterDeclaration> | undefined = funcExpr.typeParameters,
  retType: ts.TypeNode | undefined = funcExpr.type,
  modifiers: readonly ts.Modifier[] | undefined
): Autofix {
  let arrowFunc: ts.Expression = ts.factory.createArrowFunction(
    modifiers,
    typeParams,
    params,
    retType,
    ts.factory.createToken(ts.SyntaxKind.EqualsGreaterThanToken),
    funcExpr.body
  );
  if (needsParentheses(funcExpr)) {
    arrowFunc = ts.factory.createParenthesizedExpression(arrowFunc);
  }
  const text = printer.printNode(ts.EmitHint.Unspecified, arrowFunc, funcExpr.getSourceFile());
  return { start: funcExpr.getStart(), end: funcExpr.getEnd(), replacementText: text };
}

export function fixMissingReturnType(funcLikeDecl: ts.FunctionLikeDeclaration, typeNode: ts.TypeNode): Autofix {
  const text = ': ' + printer.printNode(ts.EmitHint.Unspecified, typeNode, funcLikeDecl.getSourceFile());
  const pos = getReturnTypePosition(funcLikeDecl);
  return { start: pos, end: pos, replacementText: text };
}

export function dropTypeOnVarDecl(varDecl: ts.VariableDeclaration): Autofix {
  const newVarDecl = ts.factory.createVariableDeclaration(varDecl.name, undefined, undefined, undefined);
  const text = printer.printNode(ts.EmitHint.Unspecified, newVarDecl, varDecl.getSourceFile());
  return { start: varDecl.getStart(), end: varDecl.getEnd(), replacementText: text };
}

export function fixDefaultImport(
  importClause: ts.ImportClause,
  defaultSpec: ts.ImportSpecifier,
  nonDefaultSpecs: ts.ImportSpecifier[]
): Autofix {
  const nameBindings = nonDefaultSpecs.length > 0 ? ts.factory.createNamedImports(nonDefaultSpecs) : undefined;
  const newImportClause = ts.factory.createImportClause(importClause.isTypeOnly, defaultSpec.name, nameBindings);
  const text = printer.printNode(ts.EmitHint.Unspecified, newImportClause, importClause.getSourceFile());
  return { start: importClause.getStart(), end: importClause.getEnd(), replacementText: text };
}

export function fixTypeAssertion(typeAssertion: ts.TypeAssertion): Autofix {
  const asExpr = ts.factory.createAsExpression(typeAssertion.expression, typeAssertion.type);
  const text = printer.printNode(ts.EmitHint.Unspecified, asExpr, typeAssertion.getSourceFile());
  return { start: typeAssertion.getStart(), end: typeAssertion.getEnd(), replacementText: text };
}

export function fixCommaOperator(tsNode: ts.Node): Autofix[] {
  const tsExprNode = tsNode as ts.BinaryExpression;
  const text = recursiveCommaOperator(tsExprNode);
  return [{ start: tsExprNode.parent.getStart(), end: tsExprNode.parent.getEnd(), replacementText: text }];
}

function recursiveCommaOperator(tsExprNode: ts.BinaryExpression): string {
  let text = '';
  if (tsExprNode.operatorToken.kind !== ts.SyntaxKind.CommaToken) {
    const midExpr = ts.factory.createExpressionStatement(tsExprNode);
    const midText = printer.printNode(ts.EmitHint.Unspecified, midExpr, tsExprNode.getSourceFile());
    return midText;
  }

  if (tsExprNode.left.kind === ts.SyntaxKind.BinaryExpression) {
    text += recursiveCommaOperator(tsExprNode.left as ts.BinaryExpression);

    const rightExpr = ts.factory.createExpressionStatement(tsExprNode.right);
    const rightText = printer.printNode(ts.EmitHint.Unspecified, rightExpr, tsExprNode.getSourceFile());
    text += '\n' + rightText;
  } else {
    const leftExpr = ts.factory.createExpressionStatement(tsExprNode.left);
    const rightExpr = ts.factory.createExpressionStatement(tsExprNode.right);

    const leftText = printer.printNode(ts.EmitHint.Unspecified, leftExpr, tsExprNode.getSourceFile());
    const rightText = printer.printNode(ts.EmitHint.Unspecified, rightExpr, tsExprNode.getSourceFile());
    text = leftText + '\n' + rightText;
  }

  return text;
}

export function fixEnumMerging(tsNode: ts.EnumDeclaration, members: ts.EnumMember[]): Autofix[] | undefined {
  const fullEnum = ts.factory.createEnumDeclaration(tsNode.modifiers, tsNode.name, members);
  const fullText = printer.printNode(ts.EmitHint.Unspecified, fullEnum, tsNode.getSourceFile());
  return [{ start: tsNode.getStart(), end: tsNode.getEnd(), replacementText: fullText }];
}

const printer: ts.Printer = ts.createPrinter({
  omitTrailingSemicolon: false,
  removeComments: false,
  newLine: ts.NewLineKind.LineFeed
});

function numericLiteral2IdentifierName(numeric: ts.NumericLiteral): string {
  return '__' + numeric.getText();
}

function stringLiteral2IdentifierName(str: ts.StringLiteral): string {
  const text = str.getText();
  // cut out starting and ending quoters.
  return text.substring(1, text.length - 1);
}

function propertyName2IdentifierName(name: ts.PropertyName): string {
  if (name.kind === ts.SyntaxKind.NumericLiteral) {
    return numericLiteral2IdentifierName(name);
  }

  if (name.kind === ts.SyntaxKind.StringLiteral) {
    return stringLiteral2IdentifierName(name);
  }

  return '';
}

function indexExpr2IdentifierName(index: ts.Expression): string {
  if (index.kind === ts.SyntaxKind.NumericLiteral) {
    return numericLiteral2IdentifierName(index as ts.NumericLiteral);
  }

  if (index.kind === ts.SyntaxKind.StringLiteral) {
    return stringLiteral2IdentifierName(index as ts.StringLiteral);
  }

  return '';
}

function getReturnTypePosition(funcLikeDecl: ts.FunctionLikeDeclaration): number {
  if (funcLikeDecl.body) {

    /*
     * Find position of the first node or token that follows parameters.
     * After that, iterate over child nodes in reverse order, until found
     * first closing parenthesis.
     */
    const postParametersPosition = ts.isArrowFunction(funcLikeDecl) ?
      funcLikeDecl.equalsGreaterThanToken.getStart() :
      funcLikeDecl.body.getStart();

    const children = funcLikeDecl.getChildren();
    for (let i = children.length - 1; i >= 0; i--) {
      const child = children[i];
      if (child.kind === ts.SyntaxKind.CloseParenToken && child.getEnd() <= postParametersPosition) {
        return child.getEnd();
      }
    }
  }

  // Shouldn't get here.
  return -1;
}

function needsParentheses(node: ts.FunctionExpression): boolean {
  const parent = node.parent;
  return (
    ts.isPrefixUnaryExpression(parent) ||
    ts.isPostfixUnaryExpression(parent) ||
    ts.isPropertyAccessExpression(parent) ||
    ts.isElementAccessExpression(parent) ||
    ts.isTypeOfExpression(parent) ||
    ts.isVoidExpression(parent) ||
    ts.isAwaitExpression(parent) ||
    ts.isCallExpression(parent) && node === parent.expression ||
    ts.isBinaryExpression(parent) && !isAssignmentOperator(parent.operatorToken)
  );
}

export function fixCtorParameterProperties(
  ctorDecl: ts.ConstructorDeclaration, paramTypes: ts.TypeNode[]
): Autofix[] | undefined {
  const fieldInitStmts: ts.Statement[] = [];
  const newFieldPos = ctorDecl.getStart();
  const autofixes: Autofix[] = [{ start: newFieldPos, end: newFieldPos, replacementText: '' }];

  for (let i = 0; i < ctorDecl.parameters.length; i++) {
    const param = ctorDecl.parameters[i];

    // Parameter property can not be a destructuring parameter.
    if (!ts.isIdentifier(param.name)) {
      continue;
    }

    if (TsUtils.hasAccessModifier(param)) {
      const propIdent = ts.factory.createIdentifier(param.name.text);

      const newFieldNode = ts.factory.createPropertyDeclaration(
        ts.getModifiers(param), propIdent, undefined, paramTypes[i], undefined
      );
      const newFieldText = printer.printNode(ts.EmitHint.Unspecified, newFieldNode, ctorDecl.getSourceFile()) + '\n';
      autofixes[0].replacementText += newFieldText;

      const newParamDecl = ts.factory.createParameterDeclaration(
        undefined, undefined, param.name, param.questionToken, param.type, param.initializer
      );
      const newParamText = printer.printNode(ts.EmitHint.Unspecified, newParamDecl, ctorDecl.getSourceFile());
      autofixes.push({ start: param.getStart(), end: param.getEnd(), replacementText: newParamText });

      fieldInitStmts.push(ts.factory.createExpressionStatement(ts.factory.createAssignment(
        ts.factory.createPropertyAccessExpression(
          ts.factory.createThis(),
          propIdent
        ),
        propIdent
      )));
    }
  }

  // Note: Bodyless ctors can't have parameter properties.
  if (ctorDecl.body) {
    const newBody = ts.factory.createBlock(fieldInitStmts.concat(ctorDecl.body.statements), true);
    const newBodyText = printer.printNode(ts.EmitHint.Unspecified, newBody, ctorDecl.getSourceFile());
    autofixes.push({ start: ctorDecl.body.getStart(), end: ctorDecl.body.getEnd(), replacementText: newBodyText });
  }

  return autofixes;
}

export function fixPrivateIdentifier(ident: ts.PrivateIdentifier): Autofix {
  if (
    ts.isPropertyDeclaration(ident.parent) || ts.isMethodDeclaration(ident.parent) ||
    ts.isGetAccessorDeclaration(ident.parent) || ts.isSetAccessorDeclaration(ident.parent)
  ) {
    // Note: 'private' modifier should always be first.
    const mods = ts.getModifiers(ident.parent);
    let newMods: ts.Modifier[] = [ts.factory.createModifier(ts.SyntaxKind.PrivateKeyword)];
    if (mods) {
      newMods = newMods.concat(mods);
    }

    const newName = ident.text.slice(1, ident.text.length);
    const newDecl = replacePrivateIdentInDeclarationName(newMods, newName, ident.parent);
    const text = printer.printNode(ts.EmitHint.Unspecified, newDecl, ident.getSourceFile());
    return { start: ident.parent.getStart(), end: ident.parent.getEnd(), replacementText: text };
  }

  return { start: ident.getStart(), end: ident.getEnd(), replacementText: ident.text.slice(1, ident.text.length) };
}

function replacePrivateIdentInDeclarationName(
  mods: ts.Modifier[],
  name: string,
  oldDecl: ts.PropertyDeclaration | ts.MethodDeclaration | ts.GetAccessorDeclaration | ts.SetAccessorDeclaration
): ts.Declaration {
  if (ts.isPropertyDeclaration(oldDecl)) {
    return ts.factory.createPropertyDeclaration(
      mods,
      ts.factory.createIdentifier(name),
      oldDecl.questionToken ?? oldDecl.exclamationToken,
      oldDecl.type,
      oldDecl.initializer
    );
  } else if (ts.isMethodDeclaration(oldDecl)) {
    return ts.factory.createMethodDeclaration(
      mods,
      oldDecl.asteriskToken,
      ts.factory.createIdentifier(name),
      oldDecl.questionToken,
      oldDecl.typeParameters,
      oldDecl.parameters,
      oldDecl.type,
      oldDecl.body
    );
  } else if (ts.isGetAccessorDeclaration(oldDecl)) {
    return ts.factory.createGetAccessorDeclaration(
      mods,
      ts.factory.createIdentifier(name),
      oldDecl.parameters,
      oldDecl.type,
      oldDecl.body
    );
  }
  return ts.factory.createSetAccessorDeclaration(
    mods,
    ts.factory.createIdentifier(name),
    oldDecl.parameters,
    oldDecl.body
  );
}
