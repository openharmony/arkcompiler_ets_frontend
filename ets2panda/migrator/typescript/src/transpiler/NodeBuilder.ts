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

import { CommonToken } from "antlr4ts";
import { ParseTree, TerminalNode } from "antlr4ts/tree";
import * as TranslationUtils from "./TranslationUtils";
import * as sts from "../../build/typescript/StaticTSParser";
import * as ts from "typescript";
import { StaticTSContextBase } from "../staticts/StaticTSContextBase";
import { CharStreams } from "antlr4ts";
import { StaticTSLexer } from "../../build/typescript/StaticTSLexer";

export const INVALID_NAME = "__InvalidName__";
export const UNKNOWN_TYPE_NAME = "__UnknownType__";
export const UNTRANSLATED_EXPRESSION = "__untranslated_expression";
export const UNTRANSLATED_STATEMENT = "__untranslated_statement";
export const MIGRATOR_IDENT_PREFIX = "__migrator_ident_";
export const MIGRATOR_CLASS_NAME_PREFIX = "__migrator_class_";
export const MIGRATOR_TEMP_VAR_NAME_PREFIX = "__migrator_temp_var_";
export const INVALID_EXPRESSION = "__invalid_expression";

let migratorClassCount = 0;
let migratorTempVarCount = 0;

const BOXED_BOOLEAN = "Boolean";
const BOXED_DOUBLE = "Double";
const BOXED_LONG = "Long";

export type STSTypeContext = sts.TypeReferenceContext | sts.ArrayTypeContext |
                             sts.PredefinedTypeContext | sts.FunctionTypeContext | 
                             sts.IntersectionTypeContext | sts.NullableTypeContext;

export function terminalIdentifier(tsName: string | ts.PropertyName): TerminalNode {
    let stsIdentifierName: string;

    if (typeof tsName !== 'string') {
        // Cannot translate dynamically-computed property names.
        if (ts.isComputedPropertyName(tsName)) return invalidIdentifier();

        // Process the name and create identifier.
        stsIdentifierName = tsName.text;
        if (ts.isPrivateIdentifier(tsName)) {
            // Remove leading '#' from private identifiers.
            stsIdentifierName = stsIdentifierName.slice(1, stsIdentifierName.length);
        }
    }
    else {
        stsIdentifierName = tsName;
    }

    // Check that the name is compatible with STS identifier. 
    // If not, try to salvage it by prepending a migrator-specific prefix,
    // and check again. If that fails, return __InvalidName__.
    if (isInvalidIdentifierName(stsIdentifierName)) {
        stsIdentifierName = MIGRATOR_IDENT_PREFIX + stsIdentifierName;
        if (isInvalidIdentifierName(stsIdentifierName)) return invalidIdentifier();
    }

    return terminalNode(sts.StaticTSParser.Identifier, stsIdentifierName);
}

export function invalidIdentifier(): TerminalNode {
    return terminalIdentifier(INVALID_NAME);
}

export function generatedClassName(): string {
    ++migratorClassCount;
    return MIGRATOR_CLASS_NAME_PREFIX + migratorClassCount;
}

export function temporaryVarName(): string {
    ++migratorTempVarCount;
    return MIGRATOR_TEMP_VAR_NAME_PREFIX + migratorTempVarCount;
}

function isInvalidIdentifierName(stsIdentifierName: string): boolean {
    let stsCharStream = CharStreams.fromString(stsIdentifierName);
    let stsLexer = new StaticTSLexer(stsCharStream);
    let stsTokens = stsLexer.getAllTokens();

    return (stsTokens.length !== 1 || 
            stsLexer.vocabulary.getSymbolicName(stsTokens[0].type) !== 'Identifier');
}

export function terminalNode(tokenKind: number, tokenName?: string): TerminalNode {
    if (!tokenName) tokenName = stsTokenName(tokenKind);
    return new TerminalNode(new CommonToken(tokenKind, tokenName));
}

export function terminalStringLiteral(value: string): TerminalNode {
    return new TerminalNode(new CommonToken(sts.StaticTSParser.StringLiteral, value));
}

export function stsTokenName(tokenKind: number): string {
    return sts.StaticTSParser.VOCABULARY.getLiteralName(tokenKind);
}

export function entityNameToString(fqName: ts.EntityName): string {
    if (ts.isIdentifier(fqName)) return fqName.text;

    return entityNameToString(fqName.left) + "." + fqName.right.text;
}

export function qualifiedName(fqName: ts.EntityName | string): sts.QualifiedNameContext {
    if (typeof fqName !== 'string') fqName = entityNameToString(fqName);

    let stsQualifiedName = new sts.QualifiedNameContext(undefined, 0);
    for (let name of fqName.split('.')) {
        stsQualifiedName.addChild(terminalIdentifier(name));
    }

    return stsQualifiedName;
}

export function typeReference(typeName: ts.EntityName | string): sts.TypeReferenceContext {
    let stsTypeRef = new sts.TypeReferenceContext(undefined, 0);
    let stsTypeRefPart = typeReferencePart(typeName);
    stsTypeRef.addChild(stsTypeRefPart);
    return stsTypeRef;
}

export function typeReferencePart(typeName: ts.EntityName | string): sts.TypeReferencePartContext {
    let stsTypeRefPart = new sts.TypeReferencePartContext(undefined, 0);
    stsTypeRefPart.addChild(qualifiedName(typeName));
    return stsTypeRefPart;
}

export function unknownTypeReference(tsNode?: ts.Node): sts.TypeReferenceContext {
    let stsTypeRef = typeReference(UNKNOWN_TYPE_NAME);
    // Add comment with original syntax of the type node. This should be
    // done only for non-synthesized nodes (produced by parser, not type
    // checker), otherwise the node won't have a source text to refer to,
    // and an exception might occur when attempting to call Node.getText().
    if (tsNode && !TranslationUtils.nodeIsSynthesized(tsNode)) {
        // Add comment to qualified name inside type reference
        // to ensure better readability in case type arguments
        // are added to this type reference later on.
        let stsQualifiedName = stsTypeRef.typeReferencePart(0).qualifiedName();
        stsQualifiedName.addTrailingComment(multiLineComment("/* " + tsNode.getText() + " */"));
    }
    return stsTypeRef;
}

export function typeAnnotation(stsType: STSTypeContext | string): sts.TypeAnnotationContext {
    if (typeof (stsType) === 'string') {
        let stsTypeRef = typeReference(stsType);
        return typeAnnotation(stsTypeRef);
    }

    let stsTypeAnno = new sts.TypeAnnotationContext(undefined, 0);
    let stsPrimaryType = new sts.PrimaryTypeContext(stsTypeAnno, 0);
    stsPrimaryType.addChild(stsType);
    stsTypeAnno.addChild(stsPrimaryType);
    return stsTypeAnno;
}

export function typeAliasDeclaration(stsAliasName: string, stsType: STSTypeContext | string, 
                                     stsTypeParams?: sts.TypeParametersContext): sts.TypeAliasDeclarationContext {
    if (typeof stsType === 'string') {
        let stsTypeRef = typeReference(stsType);
        return typeAliasDeclaration(stsAliasName, stsTypeRef);
    }

    let stsTypeAliasDecl = new sts.TypeAliasDeclarationContext(undefined, 0);
    stsTypeAliasDecl.addChild(terminalNode(sts.StaticTSParser.Type));
    stsTypeAliasDecl.addChild(terminalIdentifier(stsAliasName));

    if (stsTypeParams) stsTypeAliasDecl.addChild(stsTypeParams);

    let stsPrimaryType = new sts.PrimaryTypeContext(stsTypeAliasDecl, 0);
    stsPrimaryType.addChild(stsType);
    stsTypeAliasDecl.addChild(stsPrimaryType);

    return stsTypeAliasDecl;
}

export function unknownTypeAnnotation(): sts.TypeAnnotationContext {
    return typeAnnotation(UNKNOWN_TYPE_NAME);
}

export function stsBuiltinTypeName(tsTypeKind: ts.SyntaxKind): string {
    switch (tsTypeKind) {
        case ts.SyntaxKind.BooleanKeyword:
        case ts.SyntaxKind.TypePredicate:
            return BOXED_BOOLEAN;
        case ts.SyntaxKind.NumberKeyword:
            return BOXED_DOUBLE; // number type corresponds to Double
        case ts.SyntaxKind.BigIntKeyword:
            return BOXED_LONG; // TODO: BigInt doesn't have maximum limit
        case ts.SyntaxKind.StringKeyword:
            return sts.StaticTSParser.STRING;
        case ts.SyntaxKind.VoidKeyword:
            return sts.StaticTSParser.VOID;
        case ts.SyntaxKind.ObjectKeyword:
            return sts.StaticTSParser.OBJECT;
        case ts.SyntaxKind.NeverKeyword:
            return sts.StaticTSParser.NEVER;
        default:
            // TODO: Report an error?
            return null;
    }
}

export function builtinType(tsType: ts.TypeNode): sts.TypeReferenceContext {
    let stsTypeName = stsBuiltinTypeName(tsType.kind);

    // Return UNKNOWN_TYPE for unrecognized primitive type
    if (!stsTypeName) return unknownTypeReference(tsType);

    // Add a comment with original syntax if TS type is a type predicate.
    let stsTypeRef = typeReference(stsTypeName);
    if (ts.isTypePredicateNode(tsType)) {
        stsTypeRef.addTrailingComment(multiLineComment("/* " + tsType.getText() + " */"));
    }

    return stsTypeRef;
}

// STS tree:
//      singleExpression: | literal  # LiteralExpression
//      literal: NullLiteral
export function nullLiteral(): sts.SingleExpressionContext {
    let stsExpression = new sts.SingleExpressionContext(undefined, 0);
    let stsLiteralExpr = new sts.LiteralExpressionContext(stsExpression);
    let stsLiteral = new sts.LiteralContext(stsLiteralExpr, 0);
    stsLiteral.addChild(terminalNode(sts.StaticTSParser.Null));
    stsLiteralExpr.addChild(stsLiteral);
    stsExpression.addChild(stsLiteralExpr);

    return stsExpression;
}

// STS tree:
//      singleExpression: | literal  # LiteralExpression
//      literal: | BooleanLiteral
export function boolLiteral(value: boolean): sts.SingleExpressionContext {
    let stsExpression = new sts.SingleExpressionContext(undefined, 0);
    let stsLiteralExpr = new sts.LiteralExpressionContext(stsExpression);
    let stsLiteral = new sts.LiteralContext(stsLiteralExpr, 0);
    stsLiteral.addChild(terminalNode(value ? sts.StaticTSParser.True : sts.StaticTSParser.False));
    stsLiteralExpr.addChild(stsLiteral);
    stsExpression.addChild(stsLiteralExpr);

    return stsExpression;
}

// STS tree:
//      singleExpression: | literal  # LiteralExpression
//      literal: | StringLiteral
export function stringLiteral(value: string): sts.SingleExpressionContext {
    // Note: The literal value here contains original string literal delimiters.

    // ArkTS supports only double-quoted string literals, therefore, replace
    // the leading/trailing single-quotes and backticks with double-quotes. Also,
    // it is valid to have an un-escaped double-quite char in single-qupte literal.
    // Thus, escape all double-quote characteres in the literal, where needed.
    if ((value.startsWith("'") && value.endsWith("'")) || (value.startsWith("`") && value.endsWith("`"))) {
        value = '"' + escapeDoubleQuotes(value.substring(1, value.length - 1)) + '"';
    }

    // Escape XML's specific characters in the string literal.
    value = escapeXMLAttributeValue(value);

    let stsExpression = new sts.SingleExpressionContext(undefined, 0);
    let stsLiteralExpr = new sts.LiteralExpressionContext(stsExpression);
    let stsLiteral = new sts.LiteralContext(stsLiteralExpr, 0);
    stsLiteral.addChild(terminalNode(sts.StaticTSParser.StringLiteral, value));
    stsLiteralExpr.addChild(stsLiteral);
    stsExpression.addChild(stsLiteralExpr);

    return stsExpression;
}

function escapeDoubleQuotes(value: string): string {
    if (!value.includes('"')) return value;

    let newVal = "";
    let idx = 0;
    let escaping = false;

    while (idx < value.length) {
        let char = value[idx];

        if (escaping) {
            // Write escaped character as is.
            escaping = false;
        } 
        else if (char === '"') {
            // Double-quote is not escaped. Add additional backslash.
            newVal += "\\";
        }
        else if (char === '\\') {
            escaping = true;
        }

        newVal += char;
        idx++;
    }

    return newVal;
}

function escapeXMLAttributeValue(value: string): string {
    // Since we write the literal value in XML's attribute value, we need to
    // escape the '&', '<' and '"' characters with predefined XML's entities
    // as the former are not allowed in XML's attribute value. The XML reader
    // will automatically un-escape all XML's entity references afterwards.
    // For reference, see https://www.w3.org/TR/xml11/#syntax
    // NOTE: The order of escaping is important: the ampersands ('&') must be
    // escaped first to ensure that other escaped characters can be correctly
    // restored to their initial state.
    let newVal = value.replace(/[\&&]/g, "&amp;");
    newVal = newVal.replace(/[\<<]/g, "&lt;");
    newVal = newVal.replace(/[\""]/g, "&quot;");
    return newVal;
}

// STS tree:
//      singleExpression: | literal  # LiteralExpression
//      literal: | numericLiteral
//      numericLiteral:
//              : DecimalLiteral
//              | HexIntegerLiteral
//              | OctalIntegerLiteral
//              | BinaryIntegerLiteral
export function numericLiteral(value: string): sts.SingleExpressionContext {
    let stsExpression = new sts.SingleExpressionContext(undefined, 0);
    let stsLiteralExpr = new sts.LiteralExpressionContext(stsExpression);
    let stsLiteral = new sts.LiteralContext(stsLiteralExpr, 0);
    let stsNumericLiteral = new sts.NumericLiteralContext(stsLiteral, 0);
    let token: CommonToken;

    // Parse string representation to create appropriate token.
    if (value.startsWith("0b") || value.startsWith("0B")) {
        token = new CommonToken(sts.StaticTSParser.BinaryIntegerLiteral, value);
    }
    else if (value.startsWith("0x") || value.startsWith("0X")) {
        token = new CommonToken(sts.StaticTSParser.HexIntegerLiteral, value);
    }
    else if ((value.startsWith("0o") || value.startsWith("0O") || value.startsWith("0"))
            && value.length > 1 && !value.includes("89") && !value.includes(".")) {
        if (value[1] !== 'o' && value[1] !== 'O') {
            // STS octal literals start with 0o.
            value = "0o" + value.substring(1);
        }
        token = new CommonToken(sts.StaticTSParser.OctalIntegerLiteral, value);
    }
    else {
        token = new CommonToken(sts.StaticTSParser.DecimalLiteral, value);
    }

    stsNumericLiteral.addChild(new TerminalNode(token));
    stsLiteral.addChild(stsNumericLiteral);
    stsLiteralExpr.addChild(stsLiteral);
    stsExpression.addChild(stsLiteralExpr);

    return stsExpression;
}

// STS tree:
//     singleExpression: | Identifier # IdentifierExpression
export function identifierExpression(name: string | ts.PropertyName): sts.SingleExpressionContext {
    let stsExpression = new sts.SingleExpressionContext(undefined, 0);
    let stsIdentifier = new sts.IdentifierExpressionContext(stsExpression);
    stsIdentifier.addChild(terminalIdentifier(name));
    stsExpression.addChild(stsIdentifier);

    return stsExpression;
}

export function multiLineComment(comment: string): TerminalNode {
    return terminalNode(sts.StaticTSParser.MultiLineComment, escapeXMLAttributeValue(comment));
}

export function singleLineComment(comment: string): TerminalNode {
    return terminalNode(sts.StaticTSParser.SingleLineComment, escapeXMLAttributeValue(comment));
}

export function functionCallNoArgs(callName: string, comment: string): sts.SingleExpressionContext {
    let stsExpression = new sts.SingleExpressionContext(undefined, 0);
    let stsCallExpression = new sts.CallExpressionContext(stsExpression);
    stsExpression.addChild(stsCallExpression);

    let stsIdentifier = identifierExpression(callName);
    stsCallExpression.addChild(stsIdentifier);

    let stsArguments = new sts.ArgumentsContext(stsCallExpression, 0);
    stsCallExpression.addChild(stsArguments);

    let stsArgList = new sts.ExpressionSequenceContext(stsArguments, 0);
    stsArguments.addChild(stsArgList);

    // Add trailing comment (if any) to argument list to make sure the comment
    // appears inside parentheses (see StaticTSWriter.visitArguments for details)
    if (comment) stsArgList.addTrailingComment(multiLineComment("/* " + comment + " */"));

    return stsExpression;
}

export function addArgument(stsSingleExpr: sts.SingleExpressionContext, arg: sts.SingleExpressionContext): void {
    // Sanity check.
    if (stsSingleExpr.childCount != 1) return;
    let stsCallExpr = stsSingleExpr.getChild(0);
    if (!(stsCallExpr instanceof sts.CallExpressionContext)) return;

    let stsArgs = stsCallExpr.arguments().expressionSequence();
    if (!stsArgs) {
        stsArgs = new sts.ExpressionSequenceContext(undefined, 0);
        stsCallExpr.arguments().addChild(stsArgs);
    }

    stsArgs.addChild(arg);
}

export function untranslatedExpression(tsExpr: ts.Expression): sts.SingleExpressionContext {
    return functionCallNoArgs(UNTRANSLATED_EXPRESSION, tsExpr.getText());
}

export function untranslatedStatement(tsStmt: ts.Statement): sts.StatementContext {
    let stsStatement = new sts.StatementContext(undefined, 0);
    let stsExprStatement = new sts.ExpressionStatementContext(stsStatement, 0);
    stsStatement.addChild(stsExprStatement);
    stsExprStatement.addChild(functionCallNoArgs(UNTRANSLATED_STATEMENT, tsStmt.getText()));
    return stsStatement;
}

export function untranslatedForHeaderComment(tsForInOrOfStmt: ts.ForInOrOfStatement): TerminalNode {
    // Create a comment with original syntax of the For loop header.
    
    // Note: We can't use a 'getText()' call on a loop node as the result
    // would also contain a loop body. To get only the header part, retrieve
    // a substring from the SourceFile text using start position of loop
    // and end position of the closing parenthesis (the 6th child node for
    // both For-of and For-in statement nodes).
    let tsSrcFile = tsForInOrOfStmt.getSourceFile();
    let tsForHeaderText = tsSrcFile.text.substring(tsForInOrOfStmt.getStart(tsSrcFile), tsForInOrOfStmt.getChildAt(5).getEnd());
    return multiLineComment("/* " + tsForHeaderText + " */");
}

export function invalidExpression(tsExpr: ts.Expression): sts.SingleExpressionContext {
    return functionCallNoArgs(INVALID_EXPRESSION, tsExpr.getText());
}

export function assignmentOperator(tsOpToken: ts.BinaryOperatorToken): sts.AssignmentOperatorContext {
    let stsOperatorCode = -1;
    let tsTokenKind = tsOpToken.kind;
    
    if (tsTokenKind === ts.SyntaxKind.PlusEqualsToken)
        stsOperatorCode = sts.StaticTSParser.PlusAssign;
    else if (tsTokenKind === ts.SyntaxKind.MinusEqualsToken)
        stsOperatorCode = sts.StaticTSParser.MinusAssign;
    else if (tsTokenKind === ts.SyntaxKind.AsteriskEqualsToken)
        stsOperatorCode = sts.StaticTSParser.MultiplyAssign;
    else if (tsTokenKind ===  ts.SyntaxKind.SlashEqualsToken)
        stsOperatorCode = sts.StaticTSParser.DivideAssign;
    else if (tsTokenKind === ts.SyntaxKind.PercentEqualsToken)
        stsOperatorCode = sts.StaticTSParser.ModulusAssign;
    else if (tsTokenKind === ts.SyntaxKind.AmpersandEqualsToken)
        stsOperatorCode = sts.StaticTSParser.BitAndAssign;
    else if (tsTokenKind === ts.SyntaxKind.BarEqualsToken)
        stsOperatorCode = sts.StaticTSParser.BitOrAssign;
    else if (tsTokenKind === ts.SyntaxKind.CaretEqualsToken)
        stsOperatorCode = sts.StaticTSParser.BitXorAssign;
    else if (tsTokenKind === ts.SyntaxKind.LessThanLessThanEqualsToken)
        stsOperatorCode = sts.StaticTSParser.LeftShiftArithmeticAssign;
    else if (tsTokenKind === ts.SyntaxKind.GreaterThanGreaterThanEqualsToken)
        stsOperatorCode = sts.StaticTSParser.RightShiftArithmeticAssign;
    else if (tsTokenKind ===  ts.SyntaxKind.GreaterThanGreaterThanGreaterThanEqualsToken)
        stsOperatorCode = sts.StaticTSParser.RightShiftLogicalAssign;
    //else if (tsTokenKind === ts.SyntaxKind.AsteriskAsteriskEqualsToken)  
    //  Exponentiation assignment: x **= f()  

    if (stsOperatorCode == -1) return null;

    let stsAssignOp = new sts.AssignmentOperatorContext(undefined, 0);
    stsAssignOp.addChild(terminalNode(stsOperatorCode));
    return stsAssignOp;
}

export function prefixUnaryExpression(tsPrefixUnaryExpr: ts.PrefixUnaryExpression, stsOperand: sts.SingleExpressionContext): StaticTSContextBase {
    let tsPrefixUnaryOp = tsPrefixUnaryExpr.operator;
    
    let stsExpr = new sts.SingleExpressionContext(undefined, 0)
    let stsPrefixUnaryExpr: StaticTSContextBase;
    if (tsPrefixUnaryOp === ts.SyntaxKind.PlusToken)
        stsPrefixUnaryExpr = new sts.UnaryPlusExpressionContext(stsExpr);
    else if (tsPrefixUnaryOp === ts.SyntaxKind.MinusToken)
        stsPrefixUnaryExpr = new sts.UnaryMinusExpressionContext(stsExpr);
    else if (tsPrefixUnaryOp === ts.SyntaxKind.PlusPlusToken)
        stsPrefixUnaryExpr = new sts.PreIncrementExpressionContext(stsExpr);
    else if (tsPrefixUnaryOp === ts.SyntaxKind.MinusMinusToken)
        stsPrefixUnaryExpr = new sts.PreDecreaseExpressionContext(stsExpr);
    else if (tsPrefixUnaryOp === ts.SyntaxKind.ExclamationToken)
        stsPrefixUnaryExpr = new sts.NotExpressionContext(stsExpr);
    else if (tsPrefixUnaryOp === ts.SyntaxKind.TildeToken)
        stsPrefixUnaryExpr = new sts.BitNotExpressionContext(stsExpr);
    else { 
        // TODO: Report an error
        return untranslatedExpression(tsPrefixUnaryExpr);
    }
    stsExpr.addChild(stsPrefixUnaryExpr)
    stsPrefixUnaryExpr.addChild(stsOperand)

    return stsExpr;
}

export function postfixUnaryExpression(tsPostfixUnaryExpr: ts.PostfixUnaryExpression, stsOperand: sts.SingleExpressionContext): StaticTSContextBase {
    let tsPostfixUnaryOp = tsPostfixUnaryExpr.operator;
    
    let stsExpr = new sts.SingleExpressionContext(undefined, 0)
    let stsPostfixUnaryExpr: StaticTSContextBase;
    if (tsPostfixUnaryOp === ts.SyntaxKind.PlusPlusToken)
        stsPostfixUnaryExpr = new sts.PostIncrementExpressionContext(stsExpr);
    else if (tsPostfixUnaryOp === ts.SyntaxKind.MinusMinusToken)
        stsPostfixUnaryExpr = new sts.PostDecreaseExpressionContext(stsExpr);
    else { 
        // TODO: Report an error
        return untranslatedExpression(tsPostfixUnaryExpr);
    }
    stsExpr.addChild(stsPostfixUnaryExpr);
    stsPostfixUnaryExpr.addChild(stsOperand)

    return stsExpr;
}

export function binaryExpression(tsBinaryExpr: ts.BinaryExpression, stsLeftOperand: sts.SingleExpressionContext,
                    stsRightOperand: sts.SingleExpressionContext): StaticTSContextBase {
    let tsBinaryOp = tsBinaryExpr.operatorToken;
    let tsOpKind = tsBinaryOp.kind;

    let stsExpr = new sts.SingleExpressionContext(undefined, 0)
    let stsBinaryExpr: StaticTSContextBase;
    if (TranslationUtils.isShiftOperator(tsBinaryOp)) {
        stsBinaryExpr = new sts.BitShiftExpressionContext(stsExpr);
    }
    else {
        switch (tsOpKind) {
            case ts.SyntaxKind.AsteriskToken:
            case ts.SyntaxKind.SlashToken:
            case ts.SyntaxKind.PercentToken:
                stsBinaryExpr = new sts.MultiplicativeExpressionContext(stsExpr);
                break;
            case ts.SyntaxKind.PlusToken:
            case ts.SyntaxKind.MinusToken:
                stsBinaryExpr = new sts.AdditiveExpressionContext(stsExpr);
                break;
            case ts.SyntaxKind.LessThanToken:
            case ts.SyntaxKind.GreaterThanToken:
            case ts.SyntaxKind.LessThanEqualsToken:
            case ts.SyntaxKind.GreaterThanEqualsToken:
                stsBinaryExpr = new sts.RelationalExpressionContext(stsExpr);
                break;
            case ts.SyntaxKind.EqualsEqualsToken:
            case ts.SyntaxKind.ExclamationEqualsToken:
            case ts.SyntaxKind.EqualsEqualsEqualsToken:
            case ts.SyntaxKind.ExclamationEqualsEqualsToken:
                stsBinaryExpr = new sts.EqualityExpressionContext(stsExpr);
                break;
            case ts.SyntaxKind.AmpersandToken:
                stsBinaryExpr = new sts.BitAndExpressionContext(stsExpr);
                break;
            case ts.SyntaxKind.CaretToken:
                stsBinaryExpr = new sts.BitXOrExpressionContext(stsExpr);
                break;
            case ts.SyntaxKind.BarToken:
                stsBinaryExpr = new sts.BitOrExpressionContext(stsExpr);
                break;
            case ts.SyntaxKind.AmpersandAmpersandToken:
                stsBinaryExpr = new sts.LogicalAndExpressionContext(stsExpr);
                break;
            case ts.SyntaxKind.BarBarToken:
                stsBinaryExpr = new sts.LogicalOrExpressionContext(stsExpr);
                break;
            case ts.SyntaxKind.InstanceOfKeyword:
                stsBinaryExpr = new sts.InstanceofExpressionContext(stsExpr);
                break;
            case ts.SyntaxKind.QuestionQuestionToken:
                stsBinaryExpr = new sts.NullCoalescingExpressionContext(stsExpr);
                break;
            default:
                return null;
        }
    }

    stsExpr.addChild(stsBinaryExpr);
    stsBinaryExpr.addChild(stsLeftOperand);

    let stsBinaryOp = binaryOperator(tsBinaryOp);
    if (!stsBinaryOp) return null;
    
    stsBinaryExpr.addAnyChild(stsBinaryOp);
    stsBinaryOp.setParent(stsBinaryExpr);

    stsBinaryExpr.addChild(stsRightOperand);
    return stsExpr;
}

export function binaryOperator(tsBinaryOperator: ts.BinaryOperatorToken): TerminalNode | sts.ShiftOperatorContext {
    if (TranslationUtils.isShiftOperator(tsBinaryOperator)) {
        return shiftOperator(tsBinaryOperator);
    } else {
        let tsOpKind = tsBinaryOperator.kind;

        switch (tsOpKind) {
            case ts.SyntaxKind.AsteriskToken:
                return terminalNode(sts.StaticTSParser.Multiply);
            case ts.SyntaxKind.SlashToken:
                return terminalNode(sts.StaticTSParser.Divide);
            case ts.SyntaxKind.PercentToken:
                return terminalNode(sts.StaticTSParser.Modulus);
            case ts.SyntaxKind.PlusToken:
                return terminalNode(sts.StaticTSParser.Plus);
            case ts.SyntaxKind.MinusToken:
                return terminalNode(sts.StaticTSParser.Minus);
            case ts.SyntaxKind.LessThanToken:
                return terminalNode(sts.StaticTSParser.LessThan);
            case ts.SyntaxKind.GreaterThanToken:
                return terminalNode(sts.StaticTSParser.MoreThan);
            case ts.SyntaxKind.LessThanEqualsToken:
                return terminalNode(sts.StaticTSParser.LessThanEquals);
            case ts.SyntaxKind.GreaterThanEqualsToken:
                return terminalNode(sts.StaticTSParser.GreaterThanEquals);
            case ts.SyntaxKind.EqualsEqualsToken:
                return terminalNode(sts.StaticTSParser.Equals);
            case ts.SyntaxKind.ExclamationEqualsToken:
                return terminalNode(sts.StaticTSParser.NotEquals);
            case ts.SyntaxKind.EqualsEqualsEqualsToken:
                return terminalNode(sts.StaticTSParser.IdentityEquals);
            case ts.SyntaxKind.ExclamationEqualsEqualsToken:
                return terminalNode(sts.StaticTSParser.IdentityNotEquals);
            case ts.SyntaxKind.AmpersandToken:
                return terminalNode(sts.StaticTSParser.BitAnd);
            case ts.SyntaxKind.CaretToken:
                return terminalNode(sts.StaticTSParser.BitXor);
            case ts.SyntaxKind.BarToken:
                return terminalNode(sts.StaticTSParser.BitOr);
            case ts.SyntaxKind.AmpersandAmpersandToken:
                return terminalNode(sts.StaticTSParser.And);
            case ts.SyntaxKind.BarBarToken:
                return terminalNode(sts.StaticTSParser.Or);
            case ts.SyntaxKind.InstanceOfKeyword:
                return terminalNode(sts.StaticTSParser.Instanceof);
            case ts.SyntaxKind.QuestionQuestionToken:
                return terminalNode(sts.StaticTSParser.NullCoalesce);
            default:
                //TODO: Report an error
                return null;
        }
    }
}

export function shiftOperator(tsBinaryOperator: ts.BinaryOperatorToken): sts.ShiftOperatorContext {
    let stsShiftOp = new sts.ShiftOperatorContext(undefined, 0);
    let tsOpKind = tsBinaryOperator.kind;

    if (tsOpKind === ts.SyntaxKind.LessThanLessThanToken) {
        stsShiftOp.addChild(terminalNode(sts.StaticTSParser.LessThan));
        stsShiftOp.addChild(terminalNode(sts.StaticTSParser.LessThan));
    }
    else {
        stsShiftOp.addChild(terminalNode(sts.StaticTSParser.MoreThan));
        stsShiftOp.addChild(terminalNode(sts.StaticTSParser.MoreThan));

        if (tsOpKind === ts.SyntaxKind.GreaterThanGreaterThanGreaterThanToken)
            stsShiftOp.addChild(terminalNode(sts.StaticTSParser.MoreThan));
    }

    return stsShiftOp;
}

export function statement(stsSpecificStmt: StaticTSContextBase): sts.StatementContext {
    let stsStmt = new sts.StatementContext(undefined, 0);
    stsStmt.addChild(stsSpecificStmt);
    return stsStmt;
}


export function classMember(stsClassMemberDecl: StaticTSContextBase, stsModifier: number): sts.ClassMemberContext {
    let stsClassMember = new sts.ClassMemberContext(undefined, 0);
    stsClassMember.addChild(accessibilityModifier(stsModifier));
    stsClassMember.addChild(stsClassMemberDecl);
    return stsClassMember;
}

export function memberAccess(stsBaseExpr: StaticTSContextBase, stsMemberName: TerminalNode, 
                            isNullSafe: boolean = false, tsMemberName: string = null): sts.SingleExpressionContext {
    let stsSingleExpr = new sts.SingleExpressionContext(undefined, 0);
    let stsMemberAccess = new sts.MemberAccessExpressionContext(stsSingleExpr);

    stsMemberAccess.addChild(stsBaseExpr);
    
    // If this member access is null-safe, add question mark to indicate it.
    if (isNullSafe) stsMemberAccess.addChild(terminalNode(sts.StaticTSParser.QuestionMark));
    
    stsMemberAccess.addChild(stsMemberName);

    if (TranslationUtils.isInvalidOrModified(stsMemberName) && tsMemberName) {
        // Add comment with original syntax.
        let stsComment = multiLineComment("/* " + tsMemberName + " */");
        stsMemberAccess.addTrailingComment(stsComment);
    }

    stsSingleExpr.addChild(stsMemberAccess);
    return stsSingleExpr;
}

export function assignmentExpression(stsLeftOperand: StaticTSContextBase, stsRightOperand: StaticTSContextBase): sts.SingleExpressionContext {
    let stsSingleExpr = new sts.SingleExpressionContext(undefined, 0);
    let stsAssignExpr = new sts.AssignmentExpressionContext(stsSingleExpr);

    stsAssignExpr.addChild(stsLeftOperand);
    stsAssignExpr.addChild(terminalNode(sts.StaticTSParser.Assign));
    stsAssignExpr.addChild(stsRightOperand);

    stsSingleExpr.addChild(stsAssignExpr);
    return stsSingleExpr;
}

export function accessibilityModifier(stsModifier: number): sts.AccessibilityModifierContext {
    let stsAccMod = new sts.AccessibilityModifierContext(undefined, 0);
    
    switch (stsModifier) {
        case sts.StaticTSParser.Private:
        case sts.StaticTSParser.Protected:
        case sts.StaticTSParser.Public:
            stsAccMod.addChild(terminalNode(stsModifier));
            break;
        default:
            // If invalid, return public.
            stsAccMod.addChild(terminalNode(sts.StaticTSParser.Public));
    }

    return stsAccMod;
}

export function topDeclaration(stsDecl: StaticTSContextBase, isExported: boolean): sts.TopDeclarationContext {
    let stsTopDecl = new sts.TopDeclarationContext(undefined, 0);

    // Add export modifier, if necessary.
    if (isExported) stsTopDecl.addChild(terminalNode(sts.StaticTSParser.Export));

    stsTopDecl.addChild(stsDecl);
    return stsTopDecl;
}

export function namespaceMember(stsDecl: StaticTSContextBase, isExported: boolean): sts.NamespaceMemberContext {
    let stsNamespaceMember = new sts.NamespaceMemberContext(undefined, 0);

    // Add export modifier, if necessary.
    if (isExported) stsNamespaceMember.addChild(terminalNode(sts.StaticTSParser.Export));

    stsNamespaceMember.addChild(stsDecl);
    return stsNamespaceMember;
}

export function additiveExpression(stsLeftOperand: sts.SingleExpressionContext, stsRightOperand: sts.SingleExpressionContext): sts.SingleExpressionContext {
    let stsSingleExpr = new sts.SingleExpressionContext(undefined, 0);
    let stsAdditiveExpr = new sts.AdditiveExpressionContext(stsSingleExpr);
    stsSingleExpr.addChild(stsAdditiveExpr);

    stsAdditiveExpr.addChild(stsLeftOperand);
    stsAdditiveExpr.addChild(terminalNode(sts.StaticTSParser.Plus));
    stsAdditiveExpr.addChild(stsRightOperand);

    return stsSingleExpr;
}

export function parenthesizedExpression(stsExpr: sts.SingleExpressionContext): sts.SingleExpressionContext {
    let stsSingleExpr = new sts.SingleExpressionContext(undefined, 0);
    let stsParenthExpr = new sts.ParenthesizedExpressionContext(stsSingleExpr);
    stsSingleExpr.addChild(stsParenthExpr);
    stsParenthExpr.addChild(stsExpr);
    return stsSingleExpr;
}

export function wrapExpressionWithToStringCall(stsExpr: StaticTSContextBase): sts.SingleExpressionContext {
    // Wrap up expression with 'toString()' call.
    let stsCallSingleExpr = new sts.SingleExpressionContext(undefined, 0);
    let stsToStringCall = new sts.CallExpressionContext(stsCallSingleExpr);
    stsCallSingleExpr.addChild(stsToStringCall);

    let stsMemberAccess = memberAccess(stsExpr, terminalIdentifier("toString"));
    stsToStringCall.addChild(stsMemberAccess);
 
    stsToStringCall.addChild(new sts.ArgumentsContext(stsToStringCall, 0));
    return stsCallSingleExpr;
}
export function singleVariableDeclaration(varName: string, stsInitExpr: sts.SingleExpressionContext): sts.VariableOrConstantDeclarationContext {
    let stsVarOrConstDecl = new sts.VariableOrConstantDeclarationContext(undefined, 0);
    stsVarOrConstDecl.addChild(terminalNode(sts.StaticTSParser.Let));

    let stsVarDeclList = new sts.VariableDeclarationListContext(stsVarOrConstDecl, 0);
    let stsVarDecl = new sts.VariableDeclarationContext(stsVarDeclList, 0);
    stsVarDecl.addChild(terminalIdentifier(varName));
    
    let stsInitializer = new sts.InitializerContext(stsVarDecl, 0);
    if (stsInitExpr) stsInitializer.addChild(stsInitExpr)

    stsVarDecl.addChild(stsInitializer);
    stsVarDeclList.addChild(stsVarDecl);
    stsVarOrConstDecl.addChild(stsVarDeclList);

    return stsVarOrConstDecl;
}

export function singleConstantDeclaration(constName: string, stsInitExpr: sts.SingleExpressionContext): sts.VariableOrConstantDeclarationContext {
    let stsVarOrConstDecl = new sts.VariableOrConstantDeclarationContext(undefined, 0);
    stsVarOrConstDecl.addChild(terminalNode(sts.StaticTSParser.Const));

    let stsConstDeclList = new sts.ConstantDeclarationListContext(stsVarOrConstDecl, 0);
    let stsConstDecl = new sts.ConstantDeclarationContext(stsConstDeclList, 0);
    stsConstDecl.addChild(terminalIdentifier(constName));
    
    let stsInitializer = new sts.InitializerContext(stsConstDecl, 0);
    if (stsInitExpr) stsInitializer.addChild(stsInitExpr)

    stsConstDecl.addChild(stsInitializer);
    stsConstDeclList.addChild(stsConstDecl);
    stsVarOrConstDecl.addChild(stsConstDeclList);

    return stsVarOrConstDecl;
}

export function statementOrLocalDeclaration(stsStmt: StaticTSContextBase): sts.StatementOrLocalDeclarationContext {
    let stsStmtOrLocalDecl = new sts.StatementOrLocalDeclarationContext(undefined, 0);
    stsStmtOrLocalDecl.addChild(stsStmt);
    return stsStmtOrLocalDecl;
}

export function newClassInstanceExpression(stsType: string | sts.TypeReferenceContext, 
                            ...args: sts.SingleExpressionContext[]): sts.SingleExpressionContext {
    if (typeof stsType === 'string') stsType = typeReference(stsType);

    let stsSingleExpr = new sts.SingleExpressionContext(undefined, 0);
    let stsNewClassInstExpr = new sts.NewClassInstanceExpressionContext(stsSingleExpr);

    // Add 'new' token and type reference.
    stsNewClassInstExpr.addChild(terminalNode(sts.StaticTSParser.New));
    stsNewClassInstExpr.addChild(stsType);

    // Add arguments.
    let stsArgs = new sts.ArgumentsContext(stsNewClassInstExpr, 0);
    let stsArgList = new sts.ExpressionSequenceContext(stsArgs, 0);
    for (let stsArg of args) stsArgList.addChild(stsArg);
    stsArgs.addChild(stsArgList);
    stsNewClassInstExpr.addChild(stsArgs);

    stsSingleExpr.addChild(stsNewClassInstExpr);
    return stsSingleExpr;
}

export function superCall(...args: sts.SingleExpressionContext[]): sts.ConstructorCallContext {
    let stsCtorCall = new sts.ConstructorCallContext(undefined, 0);
    stsCtorCall.addChild(terminalNode(sts.StaticTSParser.Super));

    // Add arguments.
    let stsArgs = new sts.ArgumentsContext(stsCtorCall, 0);
    let stsArgList = new sts.ExpressionSequenceContext(stsArgs, 0);
    for (let stsArg of args) stsArgList.addChild(stsArg);
    stsArgs.addChild(stsArgList);
    
    stsCtorCall.addChild(stsArgs);
    return stsCtorCall;
}

export function thisExpression(): sts.SingleExpressionContext {
    let stsSingleExpr = new sts.SingleExpressionContext(undefined, 0);
    let stsThisExpr = new sts.ThisExpressionContext(stsSingleExpr);
    stsThisExpr.addChild(terminalNode(sts.StaticTSParser.This));

    stsSingleExpr.addChild(stsThisExpr);
    return stsSingleExpr;
}

export function nullableType(stsType: STSTypeContext): sts.NullableTypeContext {
    // Avoid nested nullable types.
    if (stsType.ruleIndex === sts.StaticTSParser.RULE_nullableType)
        return stsType as sts.NullableTypeContext;

    let stsNullableType = new sts.NullableTypeContext(undefined, 0);
    stsNullableType.addChild(stsType);
    return stsNullableType;
}
