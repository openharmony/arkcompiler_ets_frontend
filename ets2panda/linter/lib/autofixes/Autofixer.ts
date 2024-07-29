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
import { TsUtils } from '../utils/TsUtils';
import { scopeContainsThis } from '../utils/functions/ContainsThis';
import { forEachNodeInSubtree } from '../utils/functions/ForEachNodeInSubtree';
import { NameGenerator } from '../utils/functions/NameGenerator';
import { isAssignmentOperator } from '../utils/functions/isAssignmentOperator';
import { SymbolCache } from './SymbolCache';

const GENERATED_OBJECT_LITERAL_INTERFACE_NAME = 'GeneratedObjectLiteralInterface_';
const GENERATED_OBJECT_LITERAL_INTERFACE_TRESHOLD = 1000;

const GENERATED_TYPE_LITERAL_INTERFACE_NAME = 'GeneratedTypeLiteralInterface_';
const GENERATED_TYPE_LITERAL_INTERFACE_TRESHOLD = 1000;

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
    node: ts.ElementAccessExpression,
    newName: string
  ): Autofix[] | undefined {
    const argExprKind = node.argumentExpression.kind;
    if (argExprKind !== ts.SyntaxKind.NumericLiteral && argExprKind !== ts.SyntaxKind.StringLiteral) {
      return undefined;
    }

    return [
      {
        replacementText: node.expression.getText() + '.' + newName,
        start: node.getStart(),
        end: node.getEnd()
      }
    ];
  }

  fixFunctionExpression(
    funcExpr: ts.FunctionExpression,
    // eslint-disable-next-line default-param-last
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

  private static isNodeInWhileOrIf(node: ts.Node): boolean {
    return (
      node.kind === ts.SyntaxKind.WhileStatement ||
      node.kind === ts.SyntaxKind.DoStatement ||
      node.kind === ts.SyntaxKind.IfStatement
    );
  }

  private static isNodeInForLoop(node: ts.Node): boolean {
    return (
      node.kind === ts.SyntaxKind.ForInStatement ||
      node.kind === ts.SyntaxKind.ForOfStatement ||
      node.kind === ts.SyntaxKind.ForStatement
    );
  }

  private static parentInFor(node: ts.Node): ts.Node | undefined {
    let parentNode = node.parent;
    while (parentNode) {
      if (Autofixer.isNodeInForLoop(parentNode)) {
        return parentNode;
      }
      parentNode = parentNode.parent;
    }
    return undefined;
  }

  private static parentInCaseOrWhile(varDeclList: ts.VariableDeclarationList): boolean {
    let parentNode: ts.Node = varDeclList.parent;
    while (parentNode) {
      if (parentNode.kind === ts.SyntaxKind.CaseClause || Autofixer.isNodeInWhileOrIf(parentNode)) {
        return false;
      }
      parentNode = parentNode.parent;
    }
    return true;
  }

  private static isFunctionLikeDeclarationKind(node: ts.Node): boolean {
    switch (node.kind) {
      case ts.SyntaxKind.FunctionDeclaration:
      case ts.SyntaxKind.MethodDeclaration:
      case ts.SyntaxKind.Constructor:
      case ts.SyntaxKind.GetAccessor:
      case ts.SyntaxKind.SetAccessor:
      case ts.SyntaxKind.FunctionExpression:
      case ts.SyntaxKind.ArrowFunction:
        return true;
      default:
        return false;
    }
  }

  private static findVarScope(node: ts.Node): ts.Node {
    while (node !== undefined) {
      if (node.kind === ts.SyntaxKind.Block || node.kind === ts.SyntaxKind.SourceFile) {
        break;
      }
      // eslint-disable-next-line no-param-reassign
      node = node.parent;
    }
    return node;
  }

  private static varHasScope(node: ts.Node, scope: ts.Node): boolean {
    while (node !== undefined) {
      if (node === scope) {
        return true;
      }
      // eslint-disable-next-line no-param-reassign
      node = node.parent;
    }
    return false;
  }

  private static varInFunctionForScope(node: ts.Node, scope: ts.Node): boolean {
    while (node !== undefined) {
      if (Autofixer.isFunctionLikeDeclarationKind(node)) {
        break;
      }
      // eslint-disable-next-line no-param-reassign
      node = node.parent;
    }
    // node now Function like declaration

    // node need to check that function like declaration is in scope
    if (Autofixer.varHasScope(node, scope)) {
      // var use is in function scope, which is in for scope
      return true;
    }
    return false;
  }

  private static selfDeclared(decl: ts.Node, ident: ts.Node): boolean {
    // Do not check the same node
    if (ident === decl) {
      return false;
    }

    while (ident !== undefined) {
      if (ident.kind === ts.SyntaxKind.VariableDeclaration) {
        const declName = (ident as ts.VariableDeclaration).name;
        if (declName === decl) {
          return true;
        }
      }
      // eslint-disable-next-line no-param-reassign
      ident = ident.parent;
    }
    return false;
  }

  private static analizeTDZ(decl: ts.VariableDeclaration, identifiers: ts.Node[]): boolean {
    for (const ident of identifiers) {
      if (Autofixer.selfDeclared(decl.name, ident)) {
        return false;
      }
      if (ident.pos < decl.pos) {
        return false;
      }
    }
    return true;
  }

  private static analizeScope(decl: ts.VariableDeclaration, identifiers: ts.Node[]): boolean {
    const scope = Autofixer.findVarScope(decl);
    if (scope === undefined) {
      return false;
    } else if (scope.kind === ts.SyntaxKind.Block) {
      for (const ident of identifiers) {
        if (!Autofixer.varHasScope(ident, scope)) {
          return false;
        }
      }
    } else if (scope.kind === ts.SyntaxKind.SourceFile) {
      // Do nothing
    } else {
      // Unreachable, but check it
      return false;
    }
    return true;
  }

  private static analizeFor(decl: ts.VariableDeclaration, identifiers: ts.Node[]): boolean {
    const forNode = Autofixer.parentInFor(decl);
    if (forNode) {
      // analize that var is initialized
      if (forNode.kind === ts.SyntaxKind.ForInStatement || forNode.kind === ts.SyntaxKind.ForOfStatement) {
        const typedForNode = forNode as ts.ForInOrOfStatement;
        const forVarDeclarations = (typedForNode.initializer as ts.VariableDeclarationList).declarations;
        if (forVarDeclarations.length !== 1) {
          return false;
        }
        const forVarDecl = forVarDeclarations[0];

        // our goal to skip declarations in for of/in initializer
        if (forVarDecl !== decl && decl.initializer === undefined) {
          return false;
        }
      } else if (decl.initializer === undefined) {
        return false;
      }

      // analize that var uses are only in function block
      for (const ident of identifiers) {
        if (ident !== decl && !Autofixer.varHasScope(ident, forNode)) {
          return false;
        }
      }

      // analize that var is not in function
      for (const ident of identifiers) {
        if (ident !== decl && Autofixer.varInFunctionForScope(ident, forNode)) {
          return false;
        }
      }
    }
    return true;
  }

  private checkVarDeclarations(varDeclList: ts.VariableDeclarationList): boolean {
    for (const decl of varDeclList.declarations) {
      const symbol = this.typeChecker.getSymbolAtLocation(decl.name);
      if (!symbol) {
        return false;
      }

      const identifiers = this.symbolCache.getReferences(symbol);

      const declLength = symbol.declarations?.length;
      if (!declLength || declLength >= 2) {
        return false;
      }

      // Check for var use in tdz oe self declaration
      if (!Autofixer.analizeTDZ(decl, identifiers)) {
        return false;
      }

      // Has use outside scope of declaration?
      if (!Autofixer.analizeScope(decl, identifiers)) {
        return false;
      }

      // For analisys
      if (!Autofixer.analizeFor(decl, identifiers)) {
        return false;
      }

      if (symbol.getName() === 'let') {
        return false;
      }
    }
    return true;
  }

  private canAutofixNoVar(varDeclList: ts.VariableDeclarationList): boolean {
    if (!Autofixer.parentInCaseOrWhile(varDeclList)) {
      return false;
    }

    if (!this.checkVarDeclarations(varDeclList)) {
      return false;
    }

    return true;
  }

  fixVarDeclaration(node: ts.VariableDeclarationList): Autofix[] | undefined {
    const newNode = ts.factory.createVariableDeclarationList(node.declarations, ts.NodeFlags.Let);
    const text = this.printer.printNode(ts.EmitHint.Unspecified, newNode, node.getSourceFile());
    return this.canAutofixNoVar(node) ?
      [{ start: node.getStart(), end: node.getEnd(), replacementText: text }] :
      undefined;
  }

  private getFixReturnTypeArrowFunction(funcLikeDecl: ts.FunctionLikeDeclaration, typeNode: ts.TypeNode): string {
    if (!funcLikeDecl.body) {
      return '';
    }
    const node = ts.factory.createArrowFunction(
      undefined,
      funcLikeDecl.typeParameters,
      funcLikeDecl.parameters,
      typeNode,
      ts.factory.createToken(ts.SyntaxKind.EqualsGreaterThanToken),
      funcLikeDecl.body
    );
    return this.printer.printNode(ts.EmitHint.Unspecified, node, funcLikeDecl.getSourceFile());
  }

  fixMissingReturnType(funcLikeDecl: ts.FunctionLikeDeclaration, typeNode: ts.TypeNode): Autofix[] {
    if (ts.isArrowFunction(funcLikeDecl)) {
      const text = this.getFixReturnTypeArrowFunction(funcLikeDecl, typeNode);
      const startPos = funcLikeDecl.getStart();
      const endPos = funcLikeDecl.getEnd();
      return [{ start: startPos, end: endPos, replacementText: text }];
    }
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
    const text = this.nonCommentPrinter.printNode(ts.EmitHint.Unspecified, asExpr, typeAssertion.getSourceFile());
    return [{ start: typeAssertion.getStart(), end: typeAssertion.getEnd(), replacementText: text }];
  }

  fixCommaOperator(tsNode: ts.Node): Autofix[] {
    const tsExprNode = tsNode as ts.BinaryExpression;
    const text = this.recursiveCommaOperator(tsExprNode);
    return [{ start: tsExprNode.parent.getFullStart(), end: tsExprNode.parent.getEnd(), replacementText: text }];
  }

  private recursiveCommaOperator(tsExprNode: ts.BinaryExpression): string {
    let text = '';
    if (tsExprNode.operatorToken.kind !== ts.SyntaxKind.CommaToken) {
      return tsExprNode.getFullText() + ';';
    }

    if (tsExprNode.left.kind === ts.SyntaxKind.BinaryExpression) {
      text += this.recursiveCommaOperator(tsExprNode.left as ts.BinaryExpression);
      text += '\n' + tsExprNode.right.getFullText() + ';';
    } else {
      const leftText = tsExprNode.left.getFullText();
      const rightText = tsExprNode.right.getFullText();
      text = leftText + ';\n' + rightText + ';';
    }

    return text;
  }

  private getEnumMembers(node: ts.Node, enumDeclsInFile: ts.Declaration[], result: Autofix[] | undefined): void {
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
      this.getEnumMembers(node, enumDeclsInFile, result);
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

  private readonly nonCommentPrinter: ts.Printer = ts.createPrinter({
    omitTrailingSemicolon: false,
    removeComments: true,
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
    ctorDecl: ts.ConstructorDeclaration,
    paramTypes: ts.TypeNode[] | undefined
  ): Autofix[] | undefined {
    if (paramTypes === undefined) {
      return undefined;
    }

    const fieldInitStmts: ts.Statement[] = [];
    const newFieldPos = ctorDecl.getStart();
    const autofixes: Autofix[] = [{ start: newFieldPos, end: newFieldPos, replacementText: '' }];

    for (let i = 0; i < ctorDecl.parameters.length; i++) {
      this.fixCtorParameterPropertiesProcessParam(
        ctorDecl.parameters[i],
        paramTypes[i],
        ctorDecl.getSourceFile(),
        fieldInitStmts,
        autofixes
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

    if (this.utils.hasAccessModifier(param)) {
      const propIdent = ts.factory.createIdentifier(param.name.text);

      const newFieldNode = ts.factory.createPropertyDeclaration(
        ts.getModifiers(param),
        propIdent,
        undefined,
        paramType,
        undefined
      );
      const newFieldText = this.printer.printNode(ts.EmitHint.Unspecified, newFieldNode, sourceFile) + '\n';
      autofixes[0].replacementText += newFieldText;

      const newParamDecl = ts.factory.createParameterDeclaration(
        undefined,
        undefined,
        param.name,
        param.questionToken,
        param.type,
        param.initializer
      );
      const newParamText = this.printer.printNode(ts.EmitHint.Unspecified, newParamDecl, sourceFile);
      autofixes.push({ start: param.getStart(), end: param.getEnd(), replacementText: newParamText });

      fieldInitStmts.push(
        ts.factory.createExpressionStatement(
          ts.factory.createAssignment(
            ts.factory.createPropertyAccessExpression(ts.factory.createThis(), propIdent),
            propIdent
          )
        )
      );
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
    if (!ts.isClassLike(parentDecl) || this.utils.classMemberHasDuplicateName(memberDecl, parentDecl, true)) {
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
    const hasThisKeyword =
      tsFunctionDeclaration.body === undefined ? false : scopeContainsThis(tsFunctionDeclaration.body);
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

    const declaration: ts.VariableDeclaration = ts.factory.createVariableDeclaration(
      name,
      undefined,
      typeDecl,
      arrowFunc
    );
    const list: ts.VariableDeclarationList = ts.factory.createVariableDeclarationList([declaration], ts.NodeFlags.Let);

    const statement = ts.factory.createVariableStatement(modifiers, list);
    const text = this.printer.printNode(ts.EmitHint.Unspecified, statement, tsFunctionDeclaration.getSourceFile());
    return [{ start: tsFunctionDeclaration.getStart(), end: tsFunctionDeclaration.getEnd(), replacementText: text }];
  }

  fixMultipleStaticBlocks(nodes: ts.Node[]): Autofix[] | undefined {
    const autofix: Autofix[] | undefined = [];
    let body = (nodes[0] as ts.ClassStaticBlockDeclaration).body;
    let bodyStatements: ts.Statement[] = [];
    bodyStatements = bodyStatements.concat(body.statements);
    for (let i = 1; i < nodes.length; i++) {
      bodyStatements = bodyStatements.concat((nodes[i] as ts.ClassStaticBlockDeclaration).body.statements);
      autofix[i] = { start: nodes[i].getStart(), end: nodes[i].getEnd(), replacementText: '' };
    }
    body = ts.factory.createBlock(bodyStatements, true);
    // static blocks shouldn't have modifiers
    const statickBlock = ts.factory.createClassStaticBlockDeclaration(body);
    const text = this.printer.printNode(ts.EmitHint.Unspecified, statickBlock, nodes[0].getSourceFile());
    autofix[0] = { start: nodes[0].getStart(), end: nodes[0].getEnd(), replacementText: text };
    return autofix;
  }

  private readonly privateIdentifierCache = new Map<ts.Symbol, Autofix[] | undefined>();

  private fixSinglePrivateIdentifier(ident: ts.PrivateIdentifier): Autofix {
    if (
      ts.isPropertyDeclaration(ident.parent) ||
      ts.isMethodDeclaration(ident.parent) ||
      ts.isGetAccessorDeclaration(ident.parent) ||
      ts.isSetAccessorDeclaration(ident.parent)
    ) {
      // Note: 'private' modifier should always be first.
      const mods = ts.getModifiers(ident.parent);
      const newMods: ts.Modifier[] = [ts.factory.createModifier(ts.SyntaxKind.PrivateKeyword)];
      if (mods) {
        for (const mod of mods) {
          newMods.push(ts.factory.createModifier(mod.kind));
        }
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

  fixRecordObjectLiteral(objectLiteralExpr: ts.ObjectLiteralExpression): Autofix[] | undefined {
    const autofix: Autofix[] = [];

    for (const prop of objectLiteralExpr.properties) {
      if (!prop.name) {
        return undefined;
      }
      if (this.utils.isValidRecordObjectLiteralKey(prop.name)) {
        // Skip property with a valid property key.
        continue;
      }
      if (!ts.isIdentifier(prop.name)) {
        // Can only fix identifier name.
        return undefined;
      }

      const stringLiteralName = ts.factory.createStringLiteralFromNode(prop.name, true);
      const text = this.printer.printNode(ts.EmitHint.Unspecified, stringLiteralName, prop.name.getSourceFile());
      autofix.push({ start: prop.name.getStart(), end: prop.name.getEnd(), replacementText: text });
    }

    return autofix;
  }

  fixUntypedObjectLiteral(
    objectLiteralExpr: ts.ObjectLiteralExpression,
    objectLiteralType: ts.Type | undefined
  ): Autofix[] | undefined {
    if (objectLiteralType) {

      /*
       * Special case for object literal of Record type: fix object's property names
       * by replacing identifiers with string literals.
       */
      if (this.utils.isStdRecordType(this.utils.getNonNullableType(objectLiteralType))) {
        return this.fixRecordObjectLiteral(objectLiteralExpr);
      }

      // Can't fix when object literal has a contextual type.
      return undefined;
    }

    const enclosingStmt = TsUtils.getEnclosingTopLevelStatement(objectLiteralExpr);
    if (!enclosingStmt) {
      return undefined;
    }

    const newInterfaceProps = this.getInterfacePropertiesFromObjectLiteral(objectLiteralExpr, enclosingStmt);
    if (!newInterfaceProps) {
      return undefined;
    }

    const srcFile = objectLiteralExpr.getSourceFile();
    const newInterfaceName = TsUtils.generateUniqueName(this.objectLiteralInterfaceNameGenerator, srcFile);
    if (!newInterfaceName) {
      return undefined;
    }

    return [
      this.createNewInterface(srcFile, newInterfaceName, newInterfaceProps, enclosingStmt.getStart()),
      this.fixObjectLiteralExpression(srcFile, newInterfaceName, objectLiteralExpr)
    ];
  }

  private getInterfacePropertiesFromObjectLiteral(
    objectLiteralExpr: ts.ObjectLiteralExpression,
    enclosingStmt: ts.Node
  ): ts.PropertySignature[] | undefined {
    const interfaceProps: ts.PropertySignature[] = [];
    for (const prop of objectLiteralExpr.properties) {
      const interfaceProp = this.getInterfacePropertyFromObjectLiteralElement(prop, enclosingStmt);
      if (!interfaceProp) {
        return undefined;
      }
      interfaceProps.push(interfaceProp);
    }
    return interfaceProps;
  }

  private getInterfacePropertyFromObjectLiteralElement(
    prop: ts.ObjectLiteralElementLike,
    enclosingStmt: ts.Node
  ): ts.PropertySignature | undefined {
    // Can't fix if property is not a key-value pair, or the property name is a computed value.
    if (!ts.isPropertyAssignment(prop) || ts.isComputedPropertyName(prop.name)) {
      return undefined;
    }

    const propType = this.typeChecker.getTypeAtLocation(prop);

    // Can't capture generic type parameters of enclosing declarations.
    if (this.utils.hasGenericTypeParameter(propType)) {
      return undefined;
    }

    if (Autofixer.propertyTypeIsCapturedFromEnclosingLocalScope(propType, enclosingStmt)) {
      return undefined;
    }

    const propTypeNode = this.typeChecker.typeToTypeNode(propType, undefined, ts.NodeBuilderFlags.None);
    if (!propTypeNode || !this.utils.isSupportedType(propTypeNode)) {
      return undefined;
    }

    const newProp: ts.PropertySignature = ts.factory.createPropertySignature(
      undefined,
      prop.name,
      undefined,
      propTypeNode
    );
    return newProp;
  }

  private static propertyTypeIsCapturedFromEnclosingLocalScope(type: ts.Type, enclosingStmt: ts.Node): boolean {
    const sym = type.getSymbol();
    let symNode: ts.Node | undefined = TsUtils.getDeclaration(sym);

    while (symNode) {
      if (symNode === enclosingStmt) {
        return true;
      }
      symNode = symNode.parent;
    }

    return false;
  }

  private createNewInterface(
    srcFile: ts.SourceFile,
    interfaceName: string,
    members: ts.TypeElement[],
    pos: number
  ): Autofix {
    const newInterfaceDecl = ts.factory.createInterfaceDeclaration(
      undefined,
      interfaceName,
      undefined,
      undefined,
      members
    );
    const text = this.printer.printNode(ts.EmitHint.Unspecified, newInterfaceDecl, srcFile) + '\n';
    return { start: pos, end: pos, replacementText: text };
  }

  private fixObjectLiteralExpression(
    srcFile: ts.SourceFile,
    newInterfaceName: string,
    objectLiteralExpr: ts.ObjectLiteralExpression
  ): Autofix {

    /*
     * If object literal is initializing a variable or property,
     * then simply add new 'contextual' type to the declaration.
     * Otherwise, cast object literal to newly created interface type.
     */
    if (
      (ts.isVariableDeclaration(objectLiteralExpr.parent) ||
        ts.isPropertyDeclaration(objectLiteralExpr.parent) ||
        ts.isParameter(objectLiteralExpr.parent)) &&
      !objectLiteralExpr.parent.type
    ) {
      const text = ': ' + newInterfaceName;
      const pos = Autofixer.getDeclarationTypePositionForObjectLiteral(objectLiteralExpr.parent);
      return { start: pos, end: pos, replacementText: text };
    }

    const newTypeRef = ts.factory.createTypeReferenceNode(newInterfaceName);
    let newExpr: ts.Expression = ts.factory.createAsExpression(
      ts.factory.createObjectLiteralExpression(objectLiteralExpr.properties),
      newTypeRef
    );
    if (!ts.isParenthesizedExpression(objectLiteralExpr.parent)) {
      newExpr = ts.factory.createParenthesizedExpression(newExpr);
    }
    const text = this.printer.printNode(ts.EmitHint.Unspecified, newExpr, srcFile);
    return { start: objectLiteralExpr.getStart(), end: objectLiteralExpr.getEnd(), replacementText: text };
  }

  private static getDeclarationTypePositionForObjectLiteral(
    decl: ts.VariableDeclaration | ts.PropertyDeclaration | ts.ParameterDeclaration
  ): number {
    if (ts.isPropertyDeclaration(decl)) {
      return (decl.questionToken || decl.exclamationToken || decl.name).getEnd();
    } else if (ts.isParameter(decl)) {
      return (decl.questionToken || decl.name).getEnd();
    }
    return (decl.exclamationToken || decl.name).getEnd();
  }

  private readonly objectLiteralInterfaceNameGenerator = new NameGenerator(
    GENERATED_OBJECT_LITERAL_INTERFACE_NAME,
    GENERATED_OBJECT_LITERAL_INTERFACE_TRESHOLD
  );

  /*
   * In case of type alias initialized with type literal, replace
   * entire type alias with identical interface declaration.
   */
  private proceedTypeAliasDeclaration(typeLiteral: ts.TypeLiteralNode): Autofix[] | undefined {
    if (ts.isTypeAliasDeclaration(typeLiteral.parent)) {
      const typeAlias = typeLiteral.parent;
      const newInterfaceDecl = ts.factory.createInterfaceDeclaration(
        typeAlias.modifiers,
        typeAlias.name,
        typeAlias.typeParameters,
        undefined,
        typeLiteral.members
      );
      const text = this.printer.printNode(ts.EmitHint.Unspecified, newInterfaceDecl, typeLiteral.getSourceFile());
      return [{ start: typeAlias.getStart(), end: typeAlias.getEnd(), replacementText: text }];
    }
    return undefined;
  }

  fixTypeliteral(typeLiteral: ts.TypeLiteralNode): Autofix[] | undefined {
    const typeAliasAutofix = this.proceedTypeAliasDeclaration(typeLiteral);
    if (typeAliasAutofix) {
      return typeAliasAutofix;
    }

    /*
     * Create new interface declaration with members of type literal
     * and put the interface name in place of the type literal.
     */
    const srcFile = typeLiteral.getSourceFile();
    const enclosingStmt = TsUtils.getEnclosingTopLevelStatement(typeLiteral);
    if (!enclosingStmt) {
      return undefined;
    }

    if (this.typeLiteralCapturesTypeFromEnclosingLocalScope(typeLiteral, enclosingStmt)) {
      return undefined;
    }

    const newInterfaceName = TsUtils.generateUniqueName(this.typeLiteralInterfaceNameGenerator, srcFile);
    if (!newInterfaceName) {
      return undefined;
    }
    const newInterfacePos = enclosingStmt.getStart();
    const newInterfaceDecl = ts.factory.createInterfaceDeclaration(
      undefined,
      newInterfaceName,
      undefined,
      undefined,
      typeLiteral.members
    );
    const interfaceText = this.printer.printNode(ts.EmitHint.Unspecified, newInterfaceDecl, srcFile) + '\n';

    return [
      { start: newInterfacePos, end: newInterfacePos, replacementText: interfaceText },
      { start: typeLiteral.getStart(), end: typeLiteral.getEnd(), replacementText: newInterfaceName }
    ];
  }

  typeLiteralCapturesTypeFromEnclosingLocalScope(typeLiteral: ts.TypeLiteralNode, enclosingStmt: ts.Node): boolean {
    let found = false;

    const callback = (node: ts.Node): void => {
      if (!ts.isIdentifier(node)) {
        return;
      }
      const sym = this.typeChecker.getSymbolAtLocation(node);
      let symNode: ts.Node | undefined = TsUtils.getDeclaration(sym);
      while (symNode) {
        if (symNode === typeLiteral) {
          return;
        }
        if (symNode === enclosingStmt) {
          found = true;
          return;
        }
        symNode = symNode.parent;
      }
    };

    const stopCondition = (node: ts.Node): boolean => {
      void node;
      return found;
    };

    forEachNodeInSubtree(typeLiteral, callback, stopCondition);
    return found;
  }

  // eslint-disable-next-line class-methods-use-this
  removeDecorator(decorator: ts.Decorator): Autofix[] {
    return [{ start: decorator.getStart(), end: decorator.getEnd(), replacementText: '' }];
  }

  private readonly typeLiteralInterfaceNameGenerator = new NameGenerator(
    GENERATED_TYPE_LITERAL_INTERFACE_NAME,
    GENERATED_TYPE_LITERAL_INTERFACE_TRESHOLD
  );

  private readonly symbolCache: SymbolCache;
}
