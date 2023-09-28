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

import * as ts from "typescript";

export function isStatementKindNode(tsNode: ts.Node): boolean {
    switch(tsNode.kind) {
        case ts.SyntaxKind.Block:                                                                                                                                                 
        case ts.SyntaxKind.EmptyStatement:
        case ts.SyntaxKind.VariableStatement:
        case ts.SyntaxKind.ExpressionStatement:
        case ts.SyntaxKind.IfStatement:
        case ts.SyntaxKind.DoStatement:
        case ts.SyntaxKind.WhileStatement:
        case ts.SyntaxKind.ForStatement:
        case ts.SyntaxKind.ForInStatement:
        case ts.SyntaxKind.ForOfStatement:
        case ts.SyntaxKind.ContinueStatement:
        case ts.SyntaxKind.BreakStatement:
        case ts.SyntaxKind.ReturnStatement:
        case ts.SyntaxKind.WithStatement:
        case ts.SyntaxKind.SwitchStatement:
        case ts.SyntaxKind.LabeledStatement:
        case ts.SyntaxKind.ThrowStatement:
        case ts.SyntaxKind.TryStatement:
        case ts.SyntaxKind.DebuggerStatement:
            return true;
    }
    return false;
} 


export function isAssignmentOperator(tsBinaryOperator: ts.BinaryOperatorToken): boolean {
    return tsBinaryOperator.kind >= ts.SyntaxKind.FirstAssignment && tsBinaryOperator.kind <= ts.SyntaxKind.LastAssignment;
}

export function isArrayNotTupleType(tsType: ts.TypeNode): boolean {
    if (tsType && tsType.kind && ts.isArrayTypeNode(tsType)) {
        // Check that element type is not a union type to
        // filter out tuple types induced by tuple literals.
        let tsElemType = unwrapParenthesizedType(tsType.elementType);
        return !ts.isUnionTypeNode(tsElemType);
    }

    return false;
}

export function isNumberType(tsType: ts.Type): boolean {
    return (tsType.getFlags() & (ts.TypeFlags.NumberLike)) != 0;
}

export function isBooleanType(tsType: ts.Type): boolean {
    return (tsType.getFlags() & (ts.TypeFlags.BooleanLike)) != 0;
}

export function isStringType(tsType: ts.Type): boolean {
    return (tsType.getFlags() & (ts.TypeFlags.StringLike)) != 0;
}

export function unwrapParenthesizedType(tsType: ts.TypeNode): ts.TypeNode {
    while (ts.isParenthesizedTypeNode(tsType)) {
        tsType = tsType.type;
    }

    return tsType;
}

export function findParentIf(asExpr: ts.AsExpression): ts.IfStatement | null {
    let node = asExpr.parent;

    while(node) {
        if (node.kind === ts.SyntaxKind.IfStatement) {
            return node as ts.IfStatement;
        }

        node = node.parent;
    }

    return null;
}

export function isDestructuringAssignmentLHS(tsExpr: ts.ArrayLiteralExpression | ts.ObjectLiteralExpression): boolean {
    // Check whether given expression is the LHS part of the destructuring
    // assignment (or is a nested element of destructuring pattern).

    let tsParent = tsExpr.parent;
    let tsCurrentExpr: ts.Node = tsExpr;
    while (tsParent) {
        if (ts.isBinaryExpression(tsParent) && isAssignmentOperator(tsParent.operatorToken) && tsParent.left === tsCurrentExpr)
            return true;
 
        if ((ts.isForStatement(tsParent) || ts.isForInStatement(tsParent) || ts.isForOfStatement(tsParent))
                && tsParent.initializer && tsParent.initializer === tsCurrentExpr)
            return true;

        tsCurrentExpr = tsParent;
        tsParent = tsParent.parent;
    }

    return false;
}

export function isEnumType(tsType: ts.Type): boolean {
    // Note: For some reason, test (tsType.flags & ts.TypeFlags.Enum) != 0 doesn't work here.
    // Must use SymbolFlags to figure out if this is an enum type.
    return tsType.symbol && (tsType.symbol.flags & ts.SymbolFlags.Enum) != 0;
}

export function isNumberLikeType(tsType: ts.Type): boolean {
    return (tsType.getFlags() & ts.TypeFlags.NumberLike) !== 0;
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


export function unwrapParenthesizedExpression(tsExpr: ts.Expression): ts.Expression {
    let unwrappedExpr = tsExpr;

    while (ts.isParenthesizedExpression(unwrappedExpr))
        unwrappedExpr = unwrappedExpr.expression;

    return unwrappedExpr;
}

export function symbolHasDuplicateName(symbol: ts.Symbol, tsDeclKind: ts.SyntaxKind): boolean {
    // Type Checker merges all declarations with the same name
    // in one scope into one symbol. Thus, check whether the
    // symbol of certain declaration has any declaration with
    // different syntax kind.
    let symbolDecls = symbol?.getDeclarations();
    if (symbolDecls) {
        for (const symDecl of symbolDecls) {
            // Don't count declarations with 'Identifier' syntax kind as those
            // usually depict declaring an object's property through assignment.
            if (symDecl.kind !== ts.SyntaxKind.Identifier && symDecl.kind !== tsDeclKind) {
                return true;
            }
        }
    }

    return false;
}

export function isReferenceType(tsType: ts.Type): boolean {
    let f = tsType.getFlags();

    return (f & ts.TypeFlags.InstantiableNonPrimitive) != 0
        || (f & ts.TypeFlags.Object) != 0
        || (f & ts.TypeFlags.Boolean) != 0 
        || (f & ts.TypeFlags.Enum) != 0
        || (f & ts.TypeFlags.NonPrimitive) != 0
        || (f & ts.TypeFlags.Number) != 0
        || (f & ts.TypeFlags.String) != 0;
        //|| (f & ts.TypeFlags.C)
        //|| (f & ts.TypeFlags.Instantiable) != 0
}

export function isTypeSymbol(symbol: ts.Symbol): boolean {
    return symbol && symbol.flags && ((symbol.flags & ts.SymbolFlags.Class) !== 0 || (symbol.flags & ts.SymbolFlags.Interface) !== 0);
}

// Check whether type is generic 'Array<T>' type defined in TypeScript standard library.
export function isGenericArrayType(tsType: ts.Type): boolean {
    if (isTypeReference(tsType))
        tsType = tsType.target;

    return tsType.isClassOrInterface() && tsType.getSymbol()?.getName() === "Array";
}

export function isTypeReference(tsType: ts.Type): tsType is ts.TypeReference {
    return (tsType.getFlags() & ts.TypeFlags.Object) !== 0 && ((tsType as ts.ObjectType).objectFlags & ts.ObjectFlags.Reference) !== 0;
}

export function isNullType(tsTypeNode: ts.TypeNode): boolean {
    return ts.isLiteralTypeNode(tsTypeNode) && tsTypeNode.literal.kind === ts.SyntaxKind.NullKeyword;
}

export function isThisOrSuperExpr(tsExpr: ts.Expression): boolean {
    return tsExpr.kind == ts.SyntaxKind.ThisKeyword || tsExpr.kind == ts.SyntaxKind.SuperKeyword;
}

export function isPrototypeSymbol(symbol: ts.Symbol): boolean {
    return symbol && symbol.flags && (symbol.flags & ts.SymbolFlags.Prototype) !== 0;
}

export function isFunctionSymbol(symbol: ts.Symbol): boolean {
    return symbol && symbol.flags && (symbol.flags & ts.SymbolFlags.Function) !== 0;
}

export function isAnyType(tsType: ts.Type): tsType is ts.TypeReference {
    return (tsType.getFlags() & ts.TypeFlags.Any) !== 0;
}

export function isFunctionOrMethod(tsSymbol: ts.Symbol): boolean {
    return tsSymbol && ((tsSymbol.flags & ts.SymbolFlags.Function) !== 0 ||
                        (tsSymbol.flags & ts.SymbolFlags.Method) !== 0);
}

export function isMethodAssignment(tsSymbol: ts.Symbol): boolean {
    return tsSymbol && (tsSymbol.flags & ts.SymbolFlags.Method) !== 0 &&
                       (tsSymbol.flags & ts.SymbolFlags.Assignment) !== 0;
}
