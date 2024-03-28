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
import { isAssignmentOperator } from '../utils/functions/isAssignmentOperator';
import { TsUtils } from '../utils/TsUtils';
import { scopeContainsThis } from '../utils/functions/ContainsThis';
import { SymbolCache } from './SymbolCache';

export interface Autofix {
  replacementText: string;
  start: number;
  end: number;
}

export class Autofixer {
  constructor(
    private readonly typeChecker: ts.TypeChecker,
    private readonly utils: TsUtils,
    readonly sourceFile: ts.SourceFile,
    readonly cancellationToken?: ts.CancellationToken
  ) {
    this.symbolCache = new SymbolCache(this.typeChecker, this.utils, sourceFile, cancellationToken);
  }

  fixLiteralAsPropertyNamePropertyAssignment(node: ts.PropertyAssignment): Autofix[] | undefined {
    const contextualType = this.typeChecker.getContextualType(node.parent);
    if (contextualType === undefined) {
      return undefined;
    }

    const symbol = this.utils.getPropertySymbol(contextualType, node);
    if (symbol === undefined) {
      return undefined;
    }

    return this.renameSymbolAsIdentifier(symbol);
  }

  fixLiteralAsPropertyNamePropertyName(node: ts.PropertyName): Autofix[] | undefined {
    const symbol = this.typeChecker.getSymbolAtLocation(node);
    if (symbol === undefined) {
      return undefined;
    }

    return this.renameSymbolAsIdentifier(symbol);
  }

  fixPropertyAccessByIndex(node: ts.ElementAccessExpression): Autofix[] | undefined {
    const symbol = this.typeChecker.getSymbolAtLocation(node.argumentExpression);
    if (symbol === undefined) {
      return undefined;
    }

    return this.renameSymbolAsIdentifier(symbol);
  }

  private renameSymbolAsIdentifier(symbol: ts.Symbol): Autofix[] | undefined {
    if (this.renameSymbolAsIdentifierCache.has(symbol)) {
      return this.renameSymbolAsIdentifierCache.get(symbol);
    }

    if (!TsUtils.isPropertyOfInternalClassOrInterface(symbol)) {
      this.renameSymbolAsIdentifierCache.set(symbol, undefined);
      return undefined;
    }

    const newName = this.utils.findIdentifierNameForSymbol(symbol);
    if (newName === undefined) {
      this.renameSymbolAsIdentifierCache.set(symbol, undefined);
      return undefined;
    }

    let result: Autofix[] | undefined = [];
    this.symbolCache.getReferences(symbol).forEach((node) => {
      if (result === undefined) {
        return;
      }

      let autofix: Autofix[] | undefined;
      if (ts.isPropertyDeclaration(node) || ts.isPropertyAssignment(node) || ts.isPropertySignature(node)) {
        autofix = Autofixer.renamePropertyName(node.name, newName);
      } else if (ts.isElementAccessExpression(node)) {
        autofix = Autofixer.renameElementAccessExpression(node, newName);
      }

      if (autofix === undefined) {
        result = undefined;
        return;
      }

      result.push(...autofix);
    });
    if (!result?.length) {
      result = undefined;
    }

    this.renameSymbolAsIdentifierCache.set(symbol, result);
    return result;
  }

  private readonly renameSymbolAsIdentifierCache = new Map<ts.Symbol, Autofix[] | undefined>();

  private static renamePropertyName(node: ts.PropertyName, newName: string): Autofix[] | undefined {
    if (ts.isComputedPropertyName(node)) {
      return undefined;
    }

    if (ts.isMemberName(node)) {
      if (ts.idText(node) !== newName) {
        return undefined;
      }

      return [];
    }

    return [{ replacementText: newName, start: node.getStart(), end: node.getEnd() }];
  }

  private static renameElementAccessExpression(
    node: ts.ElementAccessExpression, newName: string
  ): Autofix[] | undefined {
    const argExprKind = node.argumentExpression.kind;
    if (argExprKind !== ts.SyntaxKind.NumericLiteral && argExprKind !== ts.SyntaxKind.StringLiteral) {
      return undefined;
    }

    return [{
      replacementText: node.expression.getText() + '.' + newName,
      start: node.getStart(),
      end: node.getEnd()
    }];
  }

  fixFunctionExpression(
    funcExpr: ts.FunctionExpression,
    retType: ts.TypeNode | undefined = funcExpr.type,
    modifiers: readonly ts.Modifier[] | undefined,
    isGenerator: boolean,
    hasUnfixableReturnType: boolean
  ): Autofix[] | undefined {
    const hasThisKeyword = scopeContainsThis(funcExpr.body);
    const isCalledRecursively = this.utils.isFunctionCalledRecursively(funcExpr);
    if (isGenerator || hasThisKeyword || isCalledRecursively || hasUnfixableReturnType) {
      return undefined;
    }

    let arrowFunc: ts.Expression = ts.factory.createArrowFunction(
      modifiers,
      funcExpr.typeParameters,
      funcExpr.parameters,
      retType,
      ts.factory.createToken(ts.SyntaxKind.EqualsGreaterThanToken),
      funcExpr.body
    );
    if (Autofixer.needsParentheses(funcExpr)) {
      arrowFunc = ts.factory.createParenthesizedExpression(arrowFunc);
    }
    const text = this.printer.printNode(ts.EmitHint.Unspecified, arrowFunc, funcExpr.getSourceFile());
    return [{ start: funcExpr.getStart(), end: funcExpr.getEnd(), replacementText: text }];
  }

  fixMissingReturnType(funcLikeDecl: ts.FunctionLikeDeclaration, typeNode: ts.TypeNode): Autofix[] {
    const text = ': ' + this.printer.printNode(ts.EmitHint.Unspecified, typeNode, funcLikeDecl.getSourceFile());
    const pos = Autofixer.getReturnTypePosition(funcLikeDecl);
    return [{ start: pos, end: pos, replacementText: text }];
  }

  dropTypeOnVarDecl(varDecl: ts.VariableDeclaration): Autofix[] {
    const newVarDecl = ts.factory.createVariableDeclaration(varDecl.name, undefined, undefined, undefined);
    const text = this.printer.printNode(ts.EmitHint.Unspecified, newVarDecl, varDecl.getSourceFile());
    return [{ start: varDecl.getStart(), end: varDecl.getEnd(), replacementText: text }];
  }

  fixTypeAssertion(typeAssertion: ts.TypeAssertion): Autofix[] {
    const asExpr = ts.factory.createAsExpression(typeAssertion.expression, typeAssertion.type);
    const text = this.printer.printNode(ts.EmitHint.Unspecified, asExpr, typeAssertion.getSourceFile());
    return [{ start: typeAssertion.getStart(), end: typeAssertion.getEnd(), replacementText: text }];
  }

  fixCommaOperator(tsNode: ts.Node): Autofix[] {
    const tsExprNode = tsNode as ts.BinaryExpression;
    const text = this.recursiveCommaOperator(tsExprNode);
    return [{ start: tsExprNode.parent.getStart(), end: tsExprNode.parent.getEnd(), replacementText: text }];
  }

  private recursiveCommaOperator(tsExprNode: ts.BinaryExpression): string {
    let text = '';
    if (tsExprNode.operatorToken.kind !== ts.SyntaxKind.CommaToken) {
      const midExpr = ts.factory.createExpressionStatement(tsExprNode);
      return this.printer.printNode(ts.EmitHint.Unspecified, midExpr, tsExprNode.getSourceFile());
    }

    if (tsExprNode.left.kind === ts.SyntaxKind.BinaryExpression) {
      text += this.recursiveCommaOperator(tsExprNode.left as ts.BinaryExpression);

      const rightExpr = ts.factory.createExpressionStatement(tsExprNode.right);
      const rightText = this.printer.printNode(ts.EmitHint.Unspecified, rightExpr, tsExprNode.getSourceFile());
      text += '\n' + rightText;
    } else {
      const leftExpr = ts.factory.createExpressionStatement(tsExprNode.left);
      const rightExpr = ts.factory.createExpressionStatement(tsExprNode.right);

      const leftText = this.printer.printNode(ts.EmitHint.Unspecified, leftExpr, tsExprNode.getSourceFile());
      const rightText = this.printer.printNode(ts.EmitHint.Unspecified, rightExpr, tsExprNode.getSourceFile());
      text = leftText + '\n' + rightText;
    }

    return text;
  }

  fixEnumMerging(enumSymbol: ts.Symbol, enumDeclsInFile: ts.Declaration[]): Autofix[] | undefined {
    if (this.enumMergingCache.has(enumSymbol)) {
      return this.enumMergingCache.get(enumSymbol);
    }

    if (enumDeclsInFile.length <= 1) {
      this.enumMergingCache.set(enumSymbol, undefined);
      return undefined;
    }

    let result: Autofix[] | undefined = [];
    this.symbolCache.getReferences(enumSymbol).forEach((node) => {
      if (result === undefined || !ts.isEnumDeclaration(node)) {
        return;
      }

      if (result.length) {
        result.push({ start: node.getStart(), end: node.getEnd(), replacementText: '' });
        return;
      }

      const members: ts.EnumMember[] = [];
      for (const decl of enumDeclsInFile) {
        for (const member of (decl as ts.EnumDeclaration).members) {
          if (
            member.initializer &&
            member.initializer.kind !== ts.SyntaxKind.NumericLiteral &&
            member.initializer.kind !== ts.SyntaxKind.StringLiteral
          ) {
            result = undefined;
            return;
          }
        }
        members.push(...(decl as ts.EnumDeclaration).members);
      }

      const fullEnum = ts.factory.createEnumDeclaration(node.modifiers, node.name, members);
      const fullText = this.printer.printNode(ts.EmitHint.Unspecified, fullEnum, node.getSourceFile());
      result.push({ start: node.getStart(), end: node.getEnd(), replacementText: fullText });
    });
    if (!result?.length) {
      result = undefined;
    }

    this.enumMergingCache.set(enumSymbol, result);
    return result;
  }

  private readonly enumMergingCache = new Map<ts.Symbol, Autofix[] | undefined>();

  private readonly printer: ts.Printer = ts.createPrinter({
    omitTrailingSemicolon: false,
    removeComments: false,
    newLine: ts.NewLineKind.LineFeed
  });

  private static getReturnTypePosition(funcLikeDecl: ts.FunctionLikeDeclaration): number {
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

  private static needsParentheses(node: ts.FunctionExpression): boolean {
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

  fixCtorParameterProperties(
    ctorDecl: ts.ConstructorDeclaration, paramTypes: ts.TypeNode[] | undefined
  ): Autofix[] | undefined {
    if (paramTypes === undefined) {
      return undefined;
    }

    const fieldInitStmts: ts.Statement[] = [];
    const newFieldPos = ctorDecl.getStart();
    const autofixes: Autofix[] = [{ start: newFieldPos, end: newFieldPos, replacementText: '' }];

    for (let i = 0; i < ctorDecl.parameters.length; i++) {
      this.fixCtorParameterPropertiesProcessParam(
        ctorDecl.parameters[i], paramTypes[i], ctorDecl.getSourceFile(), fieldInitStmts, autofixes
      );
    }

    // Note: Bodyless ctors can't have parameter properties.
    if (ctorDecl.body) {
      const newBody = ts.factory.createBlock(fieldInitStmts.concat(ctorDecl.body.statements), true);
      const newBodyText = this.printer.printNode(ts.EmitHint.Unspecified, newBody, ctorDecl.getSourceFile());
      autofixes.push({ start: ctorDecl.body.getStart(), end: ctorDecl.body.getEnd(), replacementText: newBodyText });
    }

    return autofixes;
  }

  private fixCtorParameterPropertiesProcessParam(
    param: ts.ParameterDeclaration,
    paramType: ts.TypeNode,
    sourceFile: ts.SourceFile,
    fieldInitStmts: ts.Statement[],
    autofixes: Autofix[]
  ): void {
    // Parameter property can not be a destructuring parameter.
    if (!ts.isIdentifier(param.name)) {
      return;
    }

    if (TsUtils.hasAccessModifier(param)) {
      const propIdent = ts.factory.createIdentifier(param.name.text);

      const newFieldNode = ts.factory.createPropertyDeclaration(
        ts.getModifiers(param), propIdent, undefined, paramType, undefined
      );
      const newFieldText = this.printer.printNode(ts.EmitHint.Unspecified, newFieldNode, sourceFile) + '\n';
      autofixes[0].replacementText += newFieldText;

      const newParamDecl = ts.factory.createParameterDeclaration(
        undefined, undefined, param.name, param.questionToken, param.type, param.initializer
      );
      const newParamText = this.printer.printNode(ts.EmitHint.Unspecified, newParamDecl, sourceFile);
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

  fixPrivateIdentifier(node: ts.PrivateIdentifier): Autofix[] | undefined {
    const classMember = this.typeChecker.getSymbolAtLocation(node);
    if (!classMember || (classMember.getFlags() & ts.SymbolFlags.ClassMember) === 0 || !classMember.valueDeclaration) {
      return undefined;
    }

    if (this.privateIdentifierCache.has(classMember)) {
      return this.privateIdentifierCache.get(classMember);
    }

    const memberDecl = classMember.valueDeclaration as ts.ClassElement;
    const parentDecl = memberDecl.parent;
    if (!ts.isClassLike(parentDecl) || this.utils.classMemberHasDuplicateName(memberDecl, parentDecl)) {
      this.privateIdentifierCache.set(classMember, undefined);
      return undefined;
    }

    let result: Autofix[] | undefined = [];
    this.symbolCache.getReferences(classMember).forEach((ident) => {
      if (ts.isPrivateIdentifier(ident)) {
        result!.push(this.fixSinglePrivateIdentifier(ident));
      }
    });
    if (!result.length) {
      result = undefined;
    }

    this.privateIdentifierCache.set(classMember, result);
    return result;
  }

  private isFunctionDeclarationFirst(tsFunctionDeclaration: ts.FunctionDeclaration): boolean {
    if (tsFunctionDeclaration.name === undefined) {
      return false;
    }

    const symbol = this.typeChecker.getSymbolAtLocation(tsFunctionDeclaration.name);
    if (symbol === undefined) {
      return false;
    }

    let minPos = tsFunctionDeclaration.pos;
    this.symbolCache.getReferences(symbol).forEach((ident) => {
      if (ident.pos < minPos) {
        minPos = ident.pos;
      }
    });

    return minPos >= tsFunctionDeclaration.pos;
  }

  fixNestedFunction(tsFunctionDeclaration: ts.FunctionDeclaration): Autofix[] | undefined {
    const isGenerator = tsFunctionDeclaration.asteriskToken !== undefined;
    const hasThisKeyword = tsFunctionDeclaration.body === undefined ?
      false :
      scopeContainsThis(tsFunctionDeclaration.body);
    const canBeFixed = !isGenerator && !hasThisKeyword;
    if (!canBeFixed) {
      return undefined;
    }

    const name = tsFunctionDeclaration.name?.escapedText;
    const type = tsFunctionDeclaration.type;
    const body = tsFunctionDeclaration.body;
    if (!name || !type || !body) {
      return undefined;
    }

    // Check only illegal decorators, cause all decorators for function declaration are illegal
    if (ts.getIllegalDecorators(tsFunctionDeclaration)) {
      return undefined;
    }

    if (!this.isFunctionDeclarationFirst(tsFunctionDeclaration)) {
      return undefined;
    }

    const typeParameters = tsFunctionDeclaration.typeParameters;
    const parameters = tsFunctionDeclaration.parameters;
    const modifiers = ts.getModifiers(tsFunctionDeclaration);

    const token = ts.factory.createToken(ts.SyntaxKind.EqualsGreaterThanToken);
    const typeDecl = ts.factory.createFunctionTypeNode(typeParameters, parameters, type);
    const arrowFunc = ts.factory.createArrowFunction(modifiers, typeParameters, parameters, type, token, body);

    const declaration: ts.VariableDeclaration = ts.factory.createVariableDeclaration(name,
      undefined,
      typeDecl,
      arrowFunc);
    const list: ts.VariableDeclarationList = ts.factory.createVariableDeclarationList([declaration], ts.NodeFlags.Let);

    const statement = ts.factory.createVariableStatement(modifiers, list);
    const text = this.printer.printNode(ts.EmitHint.Unspecified, statement, tsFunctionDeclaration.getSourceFile());
    return [{ start: tsFunctionDeclaration.getStart(), end: tsFunctionDeclaration.getEnd(), replacementText: text }];
  }


  private readonly privateIdentifierCache = new Map<ts.Symbol, Autofix[] | undefined>();

  private fixSinglePrivateIdentifier(ident: ts.PrivateIdentifier): Autofix {
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
      const newDecl = Autofixer.replacePrivateIdentInDeclarationName(newMods, newName, ident.parent);
      const text = this.printer.printNode(ts.EmitHint.Unspecified, newDecl, ident.getSourceFile());
      return { start: ident.parent.getStart(), end: ident.parent.getEnd(), replacementText: text };
    }

    return {
      start: ident.getStart(),
      end: ident.getEnd(),
      replacementText: ident.text.slice(1, ident.text.length)
    };
  }

  private static replacePrivateIdentInDeclarationName(
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

  private readonly symbolCache: SymbolCache;
}
