/*
 * Copyright (c) 2022-2022 Huawei Device Co., Ltd.
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

import { TerminalNode } from "antlr4ts/tree";
import * as ts from "typescript";
import * as sts from "../../build/typescript/StaticTSParser";
import * as NodeBuilder from "./NodeBuilder";
import * as NodeCloner from "../staticts/NodeCloner";

export function notStatementBlock(tsNode: ts.Node): boolean {
    return tsNode && tsNode.kind === ts.SyntaxKind.Block && 
            (ts.isFunctionLike(tsNode.parent) || 
            ts.isClassStaticBlockDeclaration(tsNode.parent) ||
            ts.isTryStatement(tsNode.parent) ||
            ts.isCatchClause(tsNode.parent));
}

export function isAssignmentOperator(tsBinaryOperator: ts.BinaryOperatorToken): boolean {
    return tsBinaryOperator.kind >= ts.SyntaxKind.FirstAssignment && tsBinaryOperator.kind <= ts.SyntaxKind.LastAssignment;
}

export function isShiftOperator(tsBinaryOperator: ts.BinaryOperatorToken): boolean {
    return tsBinaryOperator.kind === ts.SyntaxKind.LessThanLessThanToken 
        || tsBinaryOperator.kind === ts.SyntaxKind.GreaterThanGreaterThanToken
        || tsBinaryOperator.kind === ts.SyntaxKind.GreaterThanGreaterThanGreaterThanToken;
}

export function hasModifier(tsModifiers: readonly ts.Modifier[], tsModifierKind: number): boolean {
    // Sanity check.
    if (!tsModifiers) return false;

    for (let tsModifier of tsModifiers) {
        if (tsModifier.kind === tsModifierKind)
            return true;
    }

    return false;
}

export function getAccessModifierCode(tsModifiers: readonly ts.Modifier[], tsPropertyName?: ts.PropertyName): number {
    if (hasModifier(tsModifiers, ts.SyntaxKind.PrivateKeyword) || 
        (tsPropertyName && ts.isPrivateIdentifier(tsPropertyName))) {
        return sts.StaticTSParser.Private;
    }

    if (hasModifier(tsModifiers, ts.SyntaxKind.ProtectedKeyword)) {
        return sts.StaticTSParser.Protected;
    }

    return sts.StaticTSParser.Public;
}

export function isConst(tsNode: ts.Node): boolean {
    return !!(ts.getCombinedNodeFlags(tsNode) & ts.NodeFlags.Const);
}

export function isExpression(tsNode: ts.Node): tsNode is ts.Expression {
    switch (tsNode.kind) {
        case ts.SyntaxKind.ConditionalExpression:
        case ts.SyntaxKind.YieldExpression:
        case ts.SyntaxKind.ArrowFunction:
        case ts.SyntaxKind.BinaryExpression:
        case ts.SyntaxKind.SpreadElement:
        case ts.SyntaxKind.AsExpression:
        case ts.SyntaxKind.OmittedExpression:
        case ts.SyntaxKind.CommaListExpression:
        case ts.SyntaxKind.PartiallyEmittedExpression:
        case ts.SyntaxKind.PrefixUnaryExpression:
        case ts.SyntaxKind.PostfixUnaryExpression:
        case ts.SyntaxKind.DeleteExpression:
        case ts.SyntaxKind.TypeOfExpression:
        case ts.SyntaxKind.VoidExpression:
        case ts.SyntaxKind.AwaitExpression:
        case ts.SyntaxKind.TypeAssertionExpression:
        case ts.SyntaxKind.PropertyAccessExpression:
        case ts.SyntaxKind.ElementAccessExpression:
        case ts.SyntaxKind.NewExpression:
        case ts.SyntaxKind.CallExpression:
        case ts.SyntaxKind.JsxElement:
        case ts.SyntaxKind.JsxSelfClosingElement:
        case ts.SyntaxKind.JsxFragment:
        case ts.SyntaxKind.TaggedTemplateExpression:
        case ts.SyntaxKind.ArrayLiteralExpression:
        case ts.SyntaxKind.ParenthesizedExpression:
        case ts.SyntaxKind.ObjectLiteralExpression:
        case ts.SyntaxKind.ClassExpression:
        case ts.SyntaxKind.FunctionExpression:
        case ts.SyntaxKind.Identifier:
        case ts.SyntaxKind.PrivateIdentifier: // technically this is only an Expression if it's in a `#field in expr` BinaryExpression
        case ts.SyntaxKind.RegularExpressionLiteral:
        case ts.SyntaxKind.NumericLiteral:
        case ts.SyntaxKind.BigIntLiteral:
        case ts.SyntaxKind.StringLiteral:
        case ts.SyntaxKind.NoSubstitutionTemplateLiteral:
        case ts.SyntaxKind.TemplateExpression:
        case ts.SyntaxKind.TrueKeyword:
        case ts.SyntaxKind.FalseKeyword:
        case ts.SyntaxKind.NullKeyword:
        case ts.SyntaxKind.ThisKeyword:
        case ts.SyntaxKind.SuperKeyword:
        case ts.SyntaxKind.NonNullExpression:
        case ts.SyntaxKind.MetaProperty:
            return true;
        default:
            return false;
    }
}

export function isStatement(tsNode: ts.Node): tsNode is ts.Statement {
    switch (tsNode.kind) {
        case ts.SyntaxKind.Block:
        case ts.SyntaxKind.BreakStatement:
        case ts.SyntaxKind.ContinueStatement:
        case ts.SyntaxKind.DebuggerStatement:
        case ts.SyntaxKind.DoStatement:
        case ts.SyntaxKind.ExpressionStatement:
        case ts.SyntaxKind.EmptyStatement:
        case ts.SyntaxKind.ForInStatement:
        case ts.SyntaxKind.ForOfStatement:
        case ts.SyntaxKind.ForStatement:
        case ts.SyntaxKind.IfStatement:
        case ts.SyntaxKind.LabeledStatement:
        case ts.SyntaxKind.ReturnStatement:
        case ts.SyntaxKind.SwitchStatement:
        case ts.SyntaxKind.ThrowStatement:
        case ts.SyntaxKind.TryStatement:
        case ts.SyntaxKind.VariableStatement:
        case ts.SyntaxKind.WhileStatement:
        case ts.SyntaxKind.WithStatement:
        case ts.SyntaxKind.NotEmittedStatement:        
        case ts.SyntaxKind.ImportEqualsDeclaration:
        case ts.SyntaxKind.ImportDeclaration:
        case ts.SyntaxKind.NamespaceExportDeclaration:
        case ts.SyntaxKind.ExportAssignment:
        case ts.SyntaxKind.ExportDeclaration:
            return true;
        default:
            return false;
    }
}

export function isDeclaration(tsNode: ts.Node): tsNode is ts.Declaration {
    switch (tsNode.kind) {
        case ts.SyntaxKind.TypeParameter:
        case ts.SyntaxKind.Parameter:
        case ts.SyntaxKind.PropertySignature:
        case ts.SyntaxKind.PropertyDeclaration:
        case ts.SyntaxKind.MethodSignature:
        case ts.SyntaxKind.MethodDeclaration:
        case ts.SyntaxKind.ClassStaticBlockDeclaration:
        case ts.SyntaxKind.Constructor:
        case ts.SyntaxKind.GetAccessor:
        case ts.SyntaxKind.SetAccessor:
        case ts.SyntaxKind.CallSignature:
        case ts.SyntaxKind.ConstructSignature:
        case ts.SyntaxKind.IndexSignature:
        case ts.SyntaxKind.VariableDeclaration:
        case ts.SyntaxKind.FunctionDeclaration:
        case ts.SyntaxKind.ClassDeclaration:
        case ts.SyntaxKind.InterfaceDeclaration:
        case ts.SyntaxKind.TypeAliasDeclaration:
        case ts.SyntaxKind.EnumDeclaration:
        case ts.SyntaxKind.PropertyAssignment:
        case ts.SyntaxKind.ShorthandPropertyAssignment:
        case ts.SyntaxKind.SpreadAssignment:
        case ts.SyntaxKind.EnumMember:
        case ts.SyntaxKind.ModuleDeclaration:
            return true;
        default:
            return false;
    }
}

export function isCommaOperatorExpression(tsExpr: ts.Expression): tsExpr is ts.BinaryExpression {
    return ts.isBinaryExpression(tsExpr) && tsExpr.operatorToken.kind === ts.SyntaxKind.CommaToken;
}
export function isInvalidOrModified(stsIdentifier: TerminalNode): boolean {
    let stsIdentifierName = stsIdentifier.text;
    return stsIdentifierName.startsWith(NodeBuilder.MIGRATOR_IDENT_PREFIX) ||
           stsIdentifierName === NodeBuilder.INVALID_NAME;
}

export function nodeIsSynthesized(tsNode: ts.Node): boolean {
    // Note: Sometimes just checking pos and end of the 
    // current node is not enough, so check that parent
    // node is defined as well (unless this is an AST root).
    return positionIsSynthesized(tsNode.pos) || 
           positionIsSynthesized(tsNode.end) ||
           (!tsNode.parent && !ts.isSourceFile(tsNode));
}

export function positionIsSynthesized(pos: number): boolean {
    // This is a fast way of testing the following conditions:
    //  pos === undefined || pos === null || isNaN(pos) || pos < 0;
    return !(pos >= 0);
}

export function getTemplateText(tsTemplateLiteral: ts.TemplateLiteralToken): string {
    // Use original text of template literal to keep all special
    // characters and line endings for multi-line strings as is.
    let value = tsTemplateLiteral.getText();

    // For multi-line template strings, the line-endings are added
    // to literal value as a single characters, which need to be
    // escaped in a resulting literal value.
    if (value.includes('\n')) {
        let newVal = "";
        for (let char of value) {
            newVal += (char === '\n') ? "\\n" : char;
        }
        value = newVal;
    }

    // Since we use 'Node.getText()' here, the literal value may
    // contain excessive parts of original template syntax and
    // also miss backtick delimiters, which need to be restored.
    switch (tsTemplateLiteral.kind) {
        case ts.SyntaxKind.TemplateHead:
            return value.substring(0, value.length - 2) + "`";       // "` [head_string] ${"      -->     "`[head_string]`"
        case ts.SyntaxKind.TemplateMiddle:
            return "`" + value.substring(1, value.length - 2) + "`"; // "} [middle_string] ${"    -->     "`[middle_string]`"
        case ts.SyntaxKind.TemplateTail:
            return "`" + value.substring(1);                         // "} [tail_string] `"       -->     "`[tail_string]`"
        default: // ts.NoSubstitutionTemplateLiteral
            return value;                                            // return as is.
    }
}
// Returns array of strings as variable or constant declarations can declare multiple names in one go.
export function getTopDeclNames(stsTopDecl: sts.TopDeclarationContext): string[] {
    let stsClassDecl = stsTopDecl.classDeclaration();
    if (stsClassDecl) return [stsClassDecl.Identifier().text];

    let stsInterfaceDecl = stsTopDecl.interfaceDeclaration();
    if (stsInterfaceDecl) return [stsInterfaceDecl.Identifier().text];
    
    let stsEnumDecl = stsTopDecl.enumDeclaration();
    if (stsEnumDecl) return [stsEnumDecl.Identifier().text];

    let stsFunDecl = stsTopDecl.functionDeclaration();
    if (stsFunDecl) return [stsFunDecl.Identifier().text];

    let stsTypeAliasDecl = stsTopDecl.typeAliasDeclaration();
    if (stsTypeAliasDecl) return [stsTypeAliasDecl.Identifier().text];

    let result: string[] = [];
    let stsVarOrConstDecl = stsTopDecl.variableOrConstantDeclaration();
    if (stsVarOrConstDecl) {
        let stsVarDeclList = stsVarOrConstDecl.variableDeclarationList();
        let stsConstDeclList = stsVarOrConstDecl.constantDeclarationList();
        if (stsVarDeclList) {
            for (let stsVarDecl of stsVarDeclList.variableDeclaration()) {
                result.push(stsVarDecl.Identifier().text);
            }
        }
        else if (stsConstDeclList) {
            for (let stsConstDecl of stsConstDeclList.constantDeclaration()) {
                result.push(stsConstDecl.Identifier().text);
            }
        }
    }
    
    return result;
}

export function createAliasingFunction(stsFunDecl: sts.FunctionDeclarationContext, 
                                       stsAliasName: string): sts.FunctionDeclarationContext {
    let stsAliasFunDecl = new sts.FunctionDeclarationContext(undefined, 0);
    
    // Add function keyword and new (alias) name.
    stsAliasFunDecl.addChild(stsFunDecl.Function());
    stsAliasFunDecl.addChild(NodeBuilder.terminalIdentifier(stsAliasName));

    // Clone signature of the original function.
    let stsSignature = stsFunDecl.signature();
    stsAliasFunDecl.addChild(NodeCloner.cloneSignature(stsSignature));

    // Create a body that contains a call to original function
    // and returns it's return value if necessary.
    let stsBlock = new sts.BlockContext(stsAliasFunDecl, 0);
    let stsStatementOrLocalDecl = new sts.StatementOrLocalDeclarationContext(stsBlock, 0);
    let stsStatement = new sts.StatementContext(stsStatementOrLocalDecl, 0);
    let stsCallExpr = NodeBuilder.functionCallNoArgs(stsFunDecl.Identifier().text, null);

    // Pass parameters of aliasing functions as arguments to the original function call.
    let stsParamList = stsAliasFunDecl.signature().parameterList();
    if (stsParamList) {
        for (let stsParam of stsParamList.parameter()) {
            let stsArg = NodeBuilder.identifierExpression(stsParam.Identifier().text);
            NodeBuilder.addArgument(stsCallExpr, stsArg);
        }
    
        let stsVarParam = stsParamList.variadicParameter();
        if (stsVarParam) {
            let stsArg = NodeBuilder.identifierExpression(stsVarParam.Identifier().text);
            NodeBuilder.addArgument(stsCallExpr, stsArg);
        }
    }

    // Wrap original function call in return statement if its return type
    //  is non-void, otherwise wrap it in expression statement.
    if (!isVoidReturning(stsFunDecl)) {
        let stsReturnStmt = new sts.ReturnStatementContext(stsStatement, 0);
        stsReturnStmt.addChild(NodeBuilder.terminalNode(sts.StaticTSParser.Return));
        stsReturnStmt.addChild(stsCallExpr);
        stsStatement.addChild(stsReturnStmt);
    }
    else {
        let stsExprStatement = new sts.ExpressionStatementContext(stsStatement, 0);
        stsExprStatement.addChild(stsCallExpr);
        stsStatement.addChild(stsExprStatement);
    }

    stsStatementOrLocalDecl.addChild(stsStatement);
    stsBlock.addChild(stsStatementOrLocalDecl);
    stsAliasFunDecl.addChild(stsBlock);

    return stsAliasFunDecl;
}

export function isVoidReturning(stsFunDecl: sts.FunctionDeclarationContext): boolean {
    let stsTypeAnno = stsFunDecl.signature().typeAnnotation();
    return !stsTypeAnno || isVoid(stsTypeAnno.primaryType());
}

export function isVoid(stsPrimaryType: sts.PrimaryTypeContext): boolean {
    let stsTypeRef = stsPrimaryType.typeReference();
    return stsTypeRef && stsTypeRef.text === sts.StaticTSParser.VOID;
}

export function isEnumType(tsType: ts.Type): boolean {
    // Note: For some reason, test (tsType.flags & ts.TypeFlags.Enum) != 0 doesn't work here.
    // Must use SymbolFlags to figure out if this is an enum type.
    return tsType.symbol && (tsType.symbol.flags & ts.SymbolFlags.Enum) != 0;
}

export function isArrayNotTupleType(tsType: ts.TypeNode): boolean {
    if (tsType && ts.isArrayTypeNode(tsType)) {
        // Check that element type is not a union type to
        // filter out tuple types induced by tuple literals.
        let tsElemType = unwrapParenthesizedType(tsType.elementType);
        return !ts.isUnionTypeNode(tsElemType);
    }

    return false;
}

export function unwrapParenthesizedType(tsType: ts.TypeNode): ts.TypeNode {
    while (ts.isParenthesizedTypeNode(tsType)) {
        tsType = tsType.type;
    }

    return tsType;
}

export function createVarOrConstDeclaration(tsVarDeclList: ts.VariableDeclarationList): sts.VariableOrConstantDeclarationContext {
    // Add const or let keyword, as necessary.
    let stsVarOrConstDecl = new sts.VariableOrConstantDeclarationContext(undefined, 0);
    let stsTermId = isConst(tsVarDeclList) ? sts.StaticTSParser.Const : sts.StaticTSParser.Let;
    stsVarOrConstDecl.addChild(NodeBuilder.terminalNode(stsTermId));
    return stsVarOrConstDecl;
}

export function createVarOrConstDeclarationList(isConst: boolean) {
    return isConst
        ? new sts.ConstantDeclarationListContext(undefined, 0)
        : new sts.VariableDeclarationListContext(undefined, 0);
}

export function isClass(tsType: ts.Type): boolean {
    if (!tsType) return false;
    if (tsType.isClass()) return true;

    let symbol = tsType.symbol;
    return symbol && (symbol.flags & ts.SymbolFlags.Class) !== 0;
}

export function isClassOrInterface(tsType: ts.Type): boolean {
    if (!tsType) return false;
    if (tsType.isClassOrInterface()) return true;

    let symbol = tsType.symbol;
    return symbol && ((symbol.flags & ts.SymbolFlags.Class) !== 0 || 
                      (symbol.flags & ts.SymbolFlags.Interface) !== 0);
}

export function isVariable(tsSymbol: ts.Symbol): boolean {
    return tsSymbol && ((tsSymbol.flags & ts.SymbolFlags.BlockScopedVariable) !== 0 ||
                        (tsSymbol.flags & ts.SymbolFlags.FunctionScopedVariable) !== 0);
}

export function isAlias(tsSymbol: ts.Symbol): boolean {
    return tsSymbol && (tsSymbol.flags & ts.SymbolFlags.Alias) !== 0;
}

export function isThisOrSuperExpr(tsExpr: ts.Expression): boolean {
    return tsExpr.kind == ts.SyntaxKind.ThisKeyword || tsExpr.kind == ts.SyntaxKind.SuperKeyword;
}

export function findCtorDecl(stsClassDecl: sts.ClassDeclarationContext): sts.ConstructorDeclarationContext {
    for (let stsClassMember of stsClassDecl.classBody().classMember()) {
        let stsCtorDecl = stsClassMember.constructorDeclaration();
        if (stsCtorDecl && stsCtorDecl.constructorBody()) return stsCtorDecl;
    }

    return null;
}

export function isSuperCall(tsStmt: ts.Statement): boolean {
    return ts.isExpressionStatement(tsStmt) && ts.isCallExpression(tsStmt.expression) &&
            tsStmt.expression.expression.kind === ts.SyntaxKind.SuperKeyword;
}

export function isNullableType(tsUnionType: ts.UnionTypeNode): boolean {
    if (tsUnionType.types.length !== 2) return false;

    return isNullLiteralType(tsUnionType.types[0]) || isNullLiteralType(tsUnionType.types[1]);
}

export function isNullLiteralType(tsType: ts.TypeNode): boolean {
    return ts.isLiteralTypeNode(tsType) && tsType.literal.kind === ts.SyntaxKind.NullKeyword;
}

export function isValidSTSNamespaceMember(tsStmt: ts.Statement): boolean {
    // Don't allow nested namespaces, for the moment.
    return ts.isClassDeclaration(tsStmt) || ts.isInterfaceDeclaration(tsStmt) ||
           ts.isEnumDeclaration(tsStmt) || ts.isFunctionDeclaration(tsStmt) ||
           ts.isVariableStatement(tsStmt) || ts.isTypeAliasDeclaration(tsStmt);
}

export function isValidTopLevelDeclaration(tsStmt: ts.Statement): boolean {
    return isValidSTSNamespaceMember(tsStmt) || ts.isModuleDeclaration(tsStmt) ||
           ts.isImportDeclaration(tsStmt) || ts.isExportDeclaration(tsStmt) ||
           ts.isExportAssignment(tsStmt);
}

export function isValueModule(tsSymbol: ts.Symbol): boolean {
    return tsSymbol && (tsSymbol.flags & ts.SymbolFlags.ValueModule) !== 0;
}