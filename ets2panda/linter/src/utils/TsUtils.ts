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
import * as path from 'node:path';
import { STANDARD_LIBRARIES } from './consts/StandardLibraries';
import { TYPED_ARRAYS } from './consts/TypedArrays';
import { ES_OBJECT } from './consts/ESObject';
import { isIntrinsicObjectType } from './functions/isIntrinsicObjectType';
import { isStdLibraryType } from './functions/IsStdLibrary';
import { isStructDeclaration, isStructDeclarationKind } from './functions/IsStruct';
import { pathContainsDirectory } from './functions/PathHelper';
import { ARKTS_IGNORE_DIRS, ARKTS_IGNORE_FILES } from './consts/ArktsIgnorePaths';
import { isAssignmentOperator } from './functions/isAssignmentOperator';

export enum CheckType {
  Array,
  String = 'String',
  Set = 'Set',
  Map = 'Map',
  Error = 'Error'
};
export class TsUtils {
  constructor(private tsTypeChecker: ts.TypeChecker, private testMode: boolean, private advancedClassChecks: boolean) {
  }

  public isTypedArray(tsType: ts.TypeNode | undefined): boolean {
    if (tsType === undefined || !ts.isTypeReferenceNode(tsType)) {
      return false;
    }
    return TYPED_ARRAYS.includes(this.entityNameToString(tsType.typeName));
  }

  public isType(tsType: ts.TypeNode | undefined, checkType: string): boolean {
    if (tsType === undefined || !ts.isTypeReferenceNode(tsType)) {
      return false;
    }
    return this.entityNameToString(tsType.typeName) == checkType;
  }

  public entityNameToString(name: ts.EntityName): string {
    if (ts.isIdentifier(name)) {
      return name.escapedText.toString();
    } else {
      return this.entityNameToString(name.left) + this.entityNameToString(name.right);
    }
  }

  public isNumberType(tsType: ts.Type): boolean {
    if (tsType.isUnion()) {
      for (let tsCompType of tsType.types) {
        if ((tsCompType.flags & ts.TypeFlags.NumberLike) === 0) return false;
      }
      return true;
    }
    return (tsType.getFlags() & ts.TypeFlags.NumberLike) !== 0;
  }

  public isBooleanType(tsType: ts.Type): boolean {
    return (tsType.getFlags() & ts.TypeFlags.BooleanLike) !== 0;
  }

  public isStringLikeType(tsType: ts.Type): boolean {
    if (tsType.isUnion()) {
      for (let tsCompType of tsType.types) {
        if ((tsCompType.flags & ts.TypeFlags.StringLike) === 0) return false;
      }
      return true;
    }
    return (tsType.getFlags() & ts.TypeFlags.StringLike) !== 0;
  }

  public isStringType(type: ts.Type): boolean {
    return (type.getFlags() & ts.TypeFlags.String) !== 0;
  }

  public isPrimitiveEnumType(type: ts.Type, primitiveType: ts.TypeFlags): boolean {
    const isNonPrimitive = (type.flags & ts.TypeFlags.NonPrimitive) !== 0;
    if (!this.isEnumType(type) || !type.isUnion() || isNonPrimitive) {
      return false;
    }
    for (const t of type.types) {
      if ((t.flags & primitiveType) === 0) {
        return false;
      }
    }
    return true;
  }

  public isPrimitiveEnumMemberType(type: ts.Type, primitiveType: ts.TypeFlags): boolean {
    const isNonPrimitive = (type.flags & ts.TypeFlags.NonPrimitive) !== 0;
    if (!this.isEnumMemberType(type) || isNonPrimitive) {
      return false;
    }
    return (type.flags & primitiveType) !== 0;
  }

  public unwrapParenthesizedType(tsType: ts.TypeNode): ts.TypeNode {
    while (ts.isParenthesizedTypeNode(tsType)) {
      tsType = tsType.type;
    }
    return tsType;
  }

  public findParentIf(asExpr: ts.AsExpression): ts.IfStatement | null {
    let node = asExpr.parent;
    while (node) {
      if (node.kind === ts.SyntaxKind.IfStatement)
        return node as ts.IfStatement;

      node = node.parent;
    }

    return null;
  }

  public isDestructuringAssignmentLHS(
    tsExpr: ts.ArrayLiteralExpression | ts.ObjectLiteralExpression
  ): boolean {
    // Check whether given expression is the LHS part of the destructuring
    // assignment (or is a nested element of destructuring pattern).
    let tsParent = tsExpr.parent;
    let tsCurrentExpr: ts.Node = tsExpr;
    while (tsParent) {
      if (
        ts.isBinaryExpression(tsParent) && isAssignmentOperator(tsParent.operatorToken) &&
        tsParent.left === tsCurrentExpr
      )
        return true;

      if (
        (ts.isForStatement(tsParent) || ts.isForInStatement(tsParent) || ts.isForOfStatement(tsParent)) &&
        tsParent.initializer && tsParent.initializer === tsCurrentExpr
      )
        return true;

      tsCurrentExpr = tsParent;
      tsParent = tsParent.parent;
    }

    return false;
  }

  public isEnumType(tsType: ts.Type): boolean {
    // Note: For some reason, test (tsType.flags & ts.TypeFlags.Enum) != 0 doesn't work here.
    // Must use SymbolFlags to figure out if this is an enum type.
    return tsType.symbol && (tsType.symbol.flags & ts.SymbolFlags.Enum) !== 0;
  }

  public isEnumMemberType(tsType: ts.Type): boolean {
    // Note: For some reason, test (tsType.flags & ts.TypeFlags.Enum) != 0 doesn't work here.
    // Must use SymbolFlags to figure out if this is an enum type.
    return tsType.symbol && (tsType.symbol.flags & ts.SymbolFlags.EnumMember) !== 0;
  }

  public isObjectLiteralType(tsType: ts.Type): boolean {
    return tsType.symbol && (tsType.symbol.flags & ts.SymbolFlags.ObjectLiteral) !== 0;
  }

  public isNumberLikeType(tsType: ts.Type): boolean {
    return (tsType.getFlags() & ts.TypeFlags.NumberLike) !== 0;
  }

  public hasModifier(tsModifiers: readonly ts.Modifier[] | undefined, tsModifierKind: number): boolean {
    // Sanity check.
    if (!tsModifiers) return false;

    for (const tsModifier of tsModifiers) {
      if (tsModifier.kind === tsModifierKind) return true;
    }

    return false;
  }

  public unwrapParenthesized(tsExpr: ts.Expression): ts.Expression {
    let unwrappedExpr = tsExpr;
    while (ts.isParenthesizedExpression(unwrappedExpr))
      unwrappedExpr = unwrappedExpr.expression;

    return unwrappedExpr;
  }

  public followIfAliased(sym: ts.Symbol): ts.Symbol {
    if ((sym.getFlags() & ts.SymbolFlags.Alias) !== 0) {
      return this.tsTypeChecker.getAliasedSymbol(sym);
    }
    return sym;
  }
  
  private trueSymbolAtLocationCache = new Map<ts.Node, ts.Symbol | null>();

  public trueSymbolAtLocation(node: ts.Node): ts.Symbol | undefined {
    let cache = this.trueSymbolAtLocationCache;
    let val = cache.get(node);
    if (val !== undefined) {
      return val !== null ? val : undefined;
    }
    let sym = this.tsTypeChecker.getSymbolAtLocation(node);
    if (sym === undefined) {
      cache.set(node, null);
      return undefined;
    }
    sym = this.followIfAliased(sym);
    cache.set(node, sym);
    return sym;
  }

  private isTypeDeclSyntaxKind(kind: ts.SyntaxKind) {
    return isStructDeclarationKind(kind) ||
      kind === ts.SyntaxKind.EnumDeclaration ||
      kind === ts.SyntaxKind.ClassDeclaration ||
      kind === ts.SyntaxKind.InterfaceDeclaration ||
      kind === ts.SyntaxKind.TypeAliasDeclaration;
  }

  public symbolHasDuplicateName(symbol: ts.Symbol, tsDeclKind: ts.SyntaxKind): boolean {
    // Type Checker merges all declarations with the same name in one scope into one symbol.
    // Thus, check whether the symbol of certain declaration has any declaration with
    // different syntax kind.
    const symbolDecls = symbol?.getDeclarations();
    if (symbolDecls) {
      for (const symDecl of symbolDecls) {
        const declKind = symDecl.kind;
        // we relax arkts-unique-names for namespace collision with class/interface/enum/type/struct
        const isNamespaceTypeCollision =
          (this.isTypeDeclSyntaxKind(declKind) && tsDeclKind === ts.SyntaxKind.ModuleDeclaration) ||
          (this.isTypeDeclSyntaxKind(tsDeclKind) && declKind === ts.SyntaxKind.ModuleDeclaration)

        // Don't count declarations with 'Identifier' syntax kind as those
        // usually depict declaring an object's property through assignment.
        if (declKind !== ts.SyntaxKind.Identifier && declKind !== tsDeclKind && !isNamespaceTypeCollision) return true;
      }
    }

    return false;
  }

  public isReferenceType(tsType: ts.Type): boolean {
    const f = tsType.getFlags();
    return (
      (f & ts.TypeFlags.InstantiableNonPrimitive) != 0 || (f & ts.TypeFlags.Object) != 0 ||
      (f & ts.TypeFlags.Boolean) != 0 || (f & ts.TypeFlags.Enum) != 0 || (f & ts.TypeFlags.NonPrimitive) != 0 ||
      (f & ts.TypeFlags.Number) != 0 || (f & ts.TypeFlags.String) != 0
    );
  }

  public isPrimitiveType(type: ts.Type): boolean {
    const f = type.getFlags();
    return (
      (f & ts.TypeFlags.Boolean) != 0 || (f & ts.TypeFlags.BooleanLiteral) != 0 ||
      (f & ts.TypeFlags.Number) != 0 || (f & ts.TypeFlags.NumberLiteral) != 0
      // In ArkTS 'string' is not a primitive type. So for the common subset 'string'
      // should be considered as a reference type. That is why next line is commented out.
      //(f & ts.TypeFlags.String) != 0 || (f & ts.TypeFlags.StringLiteral) != 0
    );
  }

  public isTypeSymbol(symbol: ts.Symbol | undefined): boolean {
    return (
      !!symbol && !!symbol.flags &&
      ((symbol.flags & ts.SymbolFlags.Class) !== 0 || (symbol.flags & ts.SymbolFlags.Interface) !== 0)
    );
  }

  // Check whether type is generic 'Array<T>' type defined in TypeScript standard library.
  public isGenericArrayType(tsType: ts.Type): tsType is ts.TypeReference {
    return (
      this.isTypeReference(tsType) && tsType.typeArguments?.length === 1 && tsType.target.typeParameters?.length === 1 &&
      tsType.getSymbol()?.getName() === 'Array'
    );
  }

  // does something similar to relatedByInheritanceOrIdentical function
  public isDerivedFrom(tsType: ts.Type, checkType: CheckType): tsType is ts.TypeReference {
    if (this.isTypeReference(tsType) && tsType.target !== tsType) tsType = tsType.target;

    const tsTypeNode = this.tsTypeChecker.typeToTypeNode(tsType, undefined, ts.NodeBuilderFlags.None);
    if (checkType == CheckType.Array && (this.isGenericArrayType(tsType) || this.isTypedArray(tsTypeNode)))
      return true;
    if (checkType != CheckType.Array && this.isType(tsTypeNode, checkType.toString()))
      return true;
    if (!tsType.symbol || !tsType.symbol.declarations) return false;

    for (let tsTypeDecl of tsType.symbol.declarations) {
      if (
        (!ts.isClassDeclaration(tsTypeDecl) && !ts.isInterfaceDeclaration(tsTypeDecl)) ||
        !tsTypeDecl.heritageClauses
      ) continue;
      for (let heritageClause of tsTypeDecl.heritageClauses) {
        if (this.processParentTypesCheck(heritageClause.types, checkType)) return true;
      }
    }

    return false;
  }

  public isTypeReference(tsType: ts.Type): tsType is ts.TypeReference {
    return (
      (tsType.getFlags() & ts.TypeFlags.Object) !== 0 &&
      ((tsType as ts.ObjectType).objectFlags & ts.ObjectFlags.Reference) !== 0
    );
  }

  public isNullType(tsTypeNode: ts.TypeNode): boolean {
    return (ts.isLiteralTypeNode(tsTypeNode) && tsTypeNode.literal.kind === ts.SyntaxKind.NullKeyword);
  }

  public isThisOrSuperExpr(tsExpr: ts.Expression): boolean {
    return (tsExpr.kind == ts.SyntaxKind.ThisKeyword || tsExpr.kind == ts.SyntaxKind.SuperKeyword);
  }

  public isPrototypeSymbol(symbol: ts.Symbol | undefined): boolean {
    return (!!symbol && !!symbol.flags && (symbol.flags & ts.SymbolFlags.Prototype) !== 0);
  }

  public isFunctionSymbol(symbol: ts.Symbol | undefined): boolean {
    return (!!symbol && !!symbol.flags && (symbol.flags & ts.SymbolFlags.Function) !== 0);
  }

  public isInterfaceType(tsType: ts.Type | undefined): boolean {
    return (
      !!tsType && !!tsType.symbol && !!tsType.symbol.flags &&
      (tsType.symbol.flags & ts.SymbolFlags.Interface) !== 0
    );
  }

  public isAnyType(tsType: ts.Type): tsType is ts.TypeReference {
    return (tsType.getFlags() & ts.TypeFlags.Any) !== 0;
  }

  public isUnknownType(tsType: ts.Type): boolean {
    return (tsType.getFlags() & ts.TypeFlags.Unknown) !== 0;
  }

  public isUnsupportedType(tsType: ts.Type): boolean {
    return (
      !!tsType.flags && ((tsType.flags & ts.TypeFlags.Any) !== 0 || (tsType.flags & ts.TypeFlags.Unknown) !== 0 ||
        (tsType.flags & ts.TypeFlags.Intersection) !== 0)
    );
  }

  public isNullableUnionType(type: ts.Type): boolean {
    if (type.isUnion()) {
      for (const t of type.types) {
        if (!!(t.flags & ts.TypeFlags.Undefined) || !!(t.flags & ts.TypeFlags.Null)) {
          return true;
        }
      }
    }
    return false;
  }

  public isFunctionOrMethod(tsSymbol: ts.Symbol | undefined): boolean {
    return (
      !!tsSymbol &&
      ((tsSymbol.flags & ts.SymbolFlags.Function) !== 0 || (tsSymbol.flags & ts.SymbolFlags.Method) !== 0)
    );
  }

  public isMethodAssignment(tsSymbol: ts.Symbol | undefined): boolean {
    return (
      !!tsSymbol &&
      ((tsSymbol.flags & ts.SymbolFlags.Method) !== 0 && (tsSymbol.flags & ts.SymbolFlags.Assignment) !== 0)
    );
  }

  public getDeclaration(tsSymbol: ts.Symbol | undefined): ts.Declaration | undefined {
    if (tsSymbol && tsSymbol.declarations && tsSymbol.declarations.length > 0)
      return tsSymbol.declarations[0];
    return undefined;
  }

  private isVarDeclaration(tsDecl: ts.Node): boolean {
    return ts.isVariableDeclaration(tsDecl) && ts.isVariableDeclarationList(tsDecl.parent);
  }

  public isValidEnumMemberInit(tsExpr: ts.Expression): boolean {
    if (this.isNumberConstantValue(tsExpr.parent as ts.EnumMember))
      return true;
    if (this.isStringConstantValue(tsExpr.parent as ts.EnumMember))
      return true;
    return this.isCompileTimeExpression(tsExpr);
  }

  public isCompileTimeExpression(tsExpr: ts.Expression): boolean {
    if (
      ts.isParenthesizedExpression(tsExpr) ||
      (ts.isAsExpression(tsExpr) && tsExpr.type.kind === ts.SyntaxKind.NumberKeyword))
      return this.isCompileTimeExpression(tsExpr.expression);

    switch (tsExpr.kind) {
      case ts.SyntaxKind.PrefixUnaryExpression:
        return this.isPrefixUnaryExprValidEnumMemberInit(tsExpr as ts.PrefixUnaryExpression);
      case ts.SyntaxKind.ParenthesizedExpression:
      case ts.SyntaxKind.BinaryExpression:
        return this.isBinaryExprValidEnumMemberInit(tsExpr as ts.BinaryExpression);
      case ts.SyntaxKind.ConditionalExpression:
        return this.isConditionalExprValidEnumMemberInit(tsExpr as ts.ConditionalExpression);
      case ts.SyntaxKind.Identifier:
        return this.isIdentifierValidEnumMemberInit(tsExpr as ts.Identifier);
      case ts.SyntaxKind.NumericLiteral:
        return true;
      case ts.SyntaxKind.StringLiteral:
        return true;
      case ts.SyntaxKind.PropertyAccessExpression: {
        // if enum member is in current enum declaration try to get value
        // if it comes from another enum consider as constant
        const propertyAccess = tsExpr as ts.PropertyAccessExpression;
        if (this.isNumberConstantValue(propertyAccess))
          return true;
        const leftHandSymbol = this.trueSymbolAtLocation(propertyAccess.expression);
        if (!leftHandSymbol)
          return false;
        const decls = leftHandSymbol.getDeclarations();
        if (!decls || decls.length !== 1)
          return false;
        return ts.isEnumDeclaration(decls[0]);
      }
      default:
        return false;
    }
  }

  private isPrefixUnaryExprValidEnumMemberInit(tsExpr: ts.PrefixUnaryExpression): boolean {
    return (this.isUnaryOpAllowedForEnumMemberInit(tsExpr.operator) && this.isCompileTimeExpression(tsExpr.operand));
  }

  private isBinaryExprValidEnumMemberInit(tsExpr: ts.BinaryExpression): boolean {
    return (
      this.isBinaryOpAllowedForEnumMemberInit(tsExpr.operatorToken) && this.isCompileTimeExpression(tsExpr.left) &&
      this.isCompileTimeExpression(tsExpr.right)
    );
  }

  private isConditionalExprValidEnumMemberInit(tsExpr: ts.ConditionalExpression): boolean {
    return (this.isCompileTimeExpression(tsExpr.whenTrue) && this.isCompileTimeExpression(tsExpr.whenFalse));
  }

  private isIdentifierValidEnumMemberInit(tsExpr: ts.Identifier): boolean {
    let tsSymbol = this.trueSymbolAtLocation(tsExpr);
    let tsDecl = this.getDeclaration(tsSymbol);
    return (!!tsDecl &&
      ((this.isVarDeclaration(tsDecl) && this.isConst(tsDecl.parent)) ||
        (tsDecl.kind === ts.SyntaxKind.EnumMember)
      )
    );
  }

  private isUnaryOpAllowedForEnumMemberInit(tsPrefixUnaryOp: ts.PrefixUnaryOperator): boolean {
    return (
      tsPrefixUnaryOp === ts.SyntaxKind.PlusToken || tsPrefixUnaryOp === ts.SyntaxKind.MinusToken ||
      tsPrefixUnaryOp === ts.SyntaxKind.TildeToken
    );
  }

  private isBinaryOpAllowedForEnumMemberInit(tsBinaryOp: ts.BinaryOperatorToken): boolean {
    return (
      tsBinaryOp.kind === ts.SyntaxKind.AsteriskToken || tsBinaryOp.kind === ts.SyntaxKind.SlashToken ||
      tsBinaryOp.kind === ts.SyntaxKind.PercentToken || tsBinaryOp.kind === ts.SyntaxKind.MinusToken ||
      tsBinaryOp.kind === ts.SyntaxKind.PlusToken || tsBinaryOp.kind === ts.SyntaxKind.LessThanLessThanToken ||
      tsBinaryOp.kind === ts.SyntaxKind.GreaterThanGreaterThanToken || tsBinaryOp.kind === ts.SyntaxKind.BarBarToken ||
      tsBinaryOp.kind === ts.SyntaxKind.GreaterThanGreaterThanGreaterThanToken ||
      tsBinaryOp.kind === ts.SyntaxKind.AmpersandToken || tsBinaryOp.kind === ts.SyntaxKind.CaretToken ||
      tsBinaryOp.kind === ts.SyntaxKind.BarToken || tsBinaryOp.kind === ts.SyntaxKind.AmpersandAmpersandToken
    );
  }

  public isConst(tsNode: ts.Node): boolean {
    return !!(ts.getCombinedNodeFlags(tsNode) & ts.NodeFlags.Const);
  }

  public isNumberConstantValue(
    tsExpr: ts.EnumMember | ts.PropertyAccessExpression | ts.ElementAccessExpression | ts.NumericLiteral
  ): boolean {

    const tsConstValue = (tsExpr.kind === ts.SyntaxKind.NumericLiteral) ?
      Number(tsExpr.getText()) :
      this.tsTypeChecker.getConstantValue(tsExpr);

    return  tsConstValue !== undefined && typeof tsConstValue === 'number';
  }

  public isIntegerConstantValue(
    tsExpr: ts.EnumMember | ts.PropertyAccessExpression | ts.ElementAccessExpression | ts.NumericLiteral
  ): boolean {

    const tsConstValue = (tsExpr.kind === ts.SyntaxKind.NumericLiteral) ?
      Number(tsExpr.getText()) :
      this.tsTypeChecker.getConstantValue(tsExpr);
    return (
      tsConstValue !== undefined && typeof tsConstValue === 'number' &&
      tsConstValue.toFixed(0) === tsConstValue.toString()
    );
  }

  public isStringConstantValue(
    tsExpr: ts.EnumMember | ts.PropertyAccessExpression | ts.ElementAccessExpression
  ): boolean {
    const tsConstValue = this.tsTypeChecker.getConstantValue(tsExpr);
    return (
      tsConstValue !== undefined && typeof tsConstValue === 'string'
    );
  }

  // Returns true iff typeA is a subtype of typeB
  public relatedByInheritanceOrIdentical(typeA: ts.Type, typeB: ts.Type): boolean {
    if (this.isTypeReference(typeA) && typeA.target !== typeA) typeA = typeA.target;
    if (this.isTypeReference(typeB) && typeB.target !== typeB) typeB = typeB.target;

    if (typeA === typeB || this.isObject(typeB)) return true;
    if (!typeA.symbol || !typeA.symbol.declarations) return false;

    for (let typeADecl of typeA.symbol.declarations) {
      if (
        (!ts.isClassDeclaration(typeADecl) && !ts.isInterfaceDeclaration(typeADecl)) ||
        !typeADecl.heritageClauses
      ) continue;
      for (let heritageClause of typeADecl.heritageClauses) {
        let processInterfaces = typeA.isClass() ? (heritageClause.token != ts.SyntaxKind.ExtendsKeyword) : true;
        if (this.processParentTypes(heritageClause.types, typeB, processInterfaces)) return true;
      }
    }

    return false;
  }

  // return true if two class types are not related by inheritance and structural identity check is needed
  public needToDeduceStructuralIdentity(lhsType: ts.Type, rhsType: ts.Type, rhsExpr: ts.Expression,
    allowPromotion: boolean = false): boolean {
    // Compare non-nullable version of types.
    lhsType = this.getNonNullableType(lhsType);
    rhsType = this.getNonNullableType(rhsType);

    if (this.isLibraryType(lhsType)) {
      return false;
    }

    if (this.isDynamicObjectAssignedToStdType(lhsType, rhsExpr)) {
      return false;
    }

    if (rhsType.isUnion()) {
      // Each Class/Interface of the RHS union type must be compatible with LHS type.
      for (const compType of rhsType.types) {
        if (this.needToDeduceStructuralIdentity(lhsType, compType, rhsExpr, allowPromotion)) {
          return true;
        }
      }
      return false;
    }

    if (lhsType.isUnion()) {
      // RHS type needs to be compatible with at least one type of the LHS union.
      for (const compType of lhsType.types) {
        if (!this.needToDeduceStructuralIdentity(compType, rhsType, rhsExpr, allowPromotion)) {
          return false;
        }
      }
      return true;
    }

    if (this.advancedClassChecks && this.isClassValueType(rhsType) && lhsType != rhsType && !this.isObjectType(lhsType)) {
      // missing exact rule
      return true;
    }

    let res = lhsType.isClassOrInterface() && rhsType.isClassOrInterface() && !this.relatedByInheritanceOrIdentical(rhsType, lhsType);

    if (allowPromotion) {
      res &&= !this.relatedByInheritanceOrIdentical(lhsType, rhsType);
    }

    return res;
  }

  private processParentTypes(parentTypes: ts.NodeArray<ts.Expression>, typeB: ts.Type, processInterfaces: boolean): boolean {
    for (let baseTypeExpr of parentTypes) {
      let baseType = this.tsTypeChecker.getTypeAtLocation(baseTypeExpr);
      if (this.isTypeReference(baseType) && baseType.target !== baseType) baseType = baseType.target;
      if (baseType && (baseType.isClass() != processInterfaces) && this.relatedByInheritanceOrIdentical(baseType, typeB)) return true;
    }
    return false;
  }

  private processParentTypesCheck(parentTypes: ts.NodeArray<ts.Expression>, checkType: CheckType): boolean {
    for (let baseTypeExpr of parentTypes) {
      let baseType = this.tsTypeChecker.getTypeAtLocation(baseTypeExpr);
      if (this.isTypeReference(baseType) && baseType.target !== baseType) baseType = baseType.target;
      if (baseType && this.isDerivedFrom(baseType, checkType)) return true;
    }
    return false;
  }

  public isObject(tsType: ts.Type): boolean {
    if (!tsType) {
      return false;
    }
    if (tsType.symbol && (tsType.isClassOrInterface() && tsType.symbol.name === 'Object')) {
      return true;
    }
    let node = this.tsTypeChecker.typeToTypeNode(tsType, undefined, undefined);
    return node != undefined && node.kind === ts.SyntaxKind.ObjectKeyword;
  }

  public isCallToFunctionWithOmittedReturnType(tsExpr: ts.Expression): boolean {
    if (ts.isCallExpression(tsExpr)) {
      let tsCallSignature = this.tsTypeChecker.getResolvedSignature(tsExpr);
      if (tsCallSignature) {
        const tsSignDecl = tsCallSignature.getDeclaration();
        // `tsSignDecl` is undefined when `getResolvedSignature` returns `unknownSignature`
        if (!tsSignDecl || !tsSignDecl.type) return true;
      }
    }

    return false;
  }

  private hasReadonlyFields(type: ts.Type): boolean {
    if (type.symbol.members === undefined) return false; // No members -> no readonly fields

    let result: boolean = false;

    type.symbol.members.forEach((value, key) => {
      if (
        value.declarations !== undefined && value.declarations.length > 0 &&
        ts.isPropertyDeclaration(value.declarations[0])
      ) {
        let propmMods = ts.getModifiers(value.declarations[0] as ts.PropertyDeclaration);
        if (this.hasModifier(propmMods, ts.SyntaxKind.ReadonlyKeyword)) {
          result = true;
          return;
        }
      }
    });

    return result;
  }

  private hasDefaultCtor(type: ts.Type): boolean {
    if (type.symbol.members === undefined) return true; // No members -> no explicite constructors -> there is default ctor

    let hasCtor: boolean = false; // has any constructor
    let hasDefaultCtor: boolean = false; // has default constructor

    type.symbol.members.forEach((value, key) => {
      if ((value.flags & ts.SymbolFlags.Constructor) !== 0) {
        hasCtor = true;

        if (value.declarations !== undefined && value.declarations.length > 0) {
          let declCtor = value.declarations[0] as ts.ConstructorDeclaration;
          if (declCtor.parameters.length === 0) {
            hasDefaultCtor = true;
            return;
          }
        }
      }
    });

    return !hasCtor || hasDefaultCtor; // Has no any explicite constructor -> has implicite default constructor.
  }

  private isAbstractClass(type: ts.Type): boolean {
    if (type.isClass() && type.symbol.declarations && type.symbol.declarations.length > 0) {
      let declClass = type.symbol.declarations[0] as ts.ClassDeclaration;
      let classMods = ts.getModifiers(declClass);
      if (this.hasModifier(classMods, ts.SyntaxKind.AbstractKeyword))
        return true;
    }

    return false;
  }

  public validateObjectLiteralType(type: ts.Type | undefined): boolean {
    if (!type) {
      return false;
    }
    type = this.getTargetType(type);
    return (
      type.isClassOrInterface() && this.hasDefaultCtor(type) &&
      !this.hasReadonlyFields(type) && !this.isAbstractClass(type)
    );
  }

  public hasMethods(type: ts.Type): boolean {
    const properties = this.tsTypeChecker.getPropertiesOfType(type);
    if (properties?.length) {
      for (const prop of properties) {
        if (prop.getFlags() & ts.SymbolFlags.Method) return true;
      }
    }
    return false;
  }

  private findProperty(type: ts.Type, name: string): ts.Symbol | undefined {
    const properties = this.tsTypeChecker.getPropertiesOfType(type);
    if (properties?.length) {
      for (const prop of properties) {
        if (prop.name === name) return prop;
      }
    }

    return undefined;
  }

  public checkTypeSet(uType: ts.Type, predicate: (t: ts.Type) => boolean): boolean {
    if (!uType.isUnionOrIntersection()) {
      return predicate(uType);
    }
    for (let elemType of uType.types) {
      if (!this.checkTypeSet(elemType, predicate)) {
        return false;
      }
    }
    return true;
  }

  private getNonNullableType(t: ts.Type) {
    if (this.isNullableUnionType(t)) {
      return t.getNonNullableType();
    }
    return t;
  }

  public isObjectLiteralAssignable(lhsType: ts.Type | undefined, rhsExpr: ts.ObjectLiteralExpression): boolean {
    if (lhsType === undefined) {
      return false;
    }

    // Always check with the non-nullable variant of lhs type.
    lhsType = this.getNonNullableType(lhsType);

    if (lhsType.isUnion()) {
      for (const compType of lhsType.types) {
        if (this.isObjectLiteralAssignable(compType, rhsExpr)) {
          return true;
        }
      }
    }

    // Allow initializing with anything when the type
    // originates from the library.
    if (this.isAnyType(lhsType) || this.isLibraryType(lhsType)) {
      return true;
    }

    // issue 13412:
    // Allow initializing with a dynamic object when the LHS type
    // is primitive or defined in standard library.
    if (this.isDynamicObjectAssignedToStdType(lhsType, rhsExpr)) {
      return true;
    }

    // For Partial<T>, Required<T>, Readonly<T> types, validate their argument type.
    if (this.isStdPartialType(lhsType) || this.isStdRequiredType(lhsType) || this.isStdReadonlyType(lhsType)) {
      if (lhsType.aliasTypeArguments && lhsType.aliasTypeArguments.length === 1) {
        lhsType = lhsType.aliasTypeArguments[0];
      } else {
        return false;
      }
    }

    // Allow initializing Record objects with object initializer.
    // Record supports any type for a its value, but the key value
    // must be either a string or number literal.
    if (this.isStdRecordType(lhsType)) {
      return this.validateRecordObjectKeys(rhsExpr);
    }

    return this.validateObjectLiteralType(lhsType) && !this.hasMethods(lhsType) && this.validateFields(lhsType, rhsExpr);
  }

  isFunctionalType(type: ts.Type): boolean {
    const callSigns = type.getCallSignatures();
    return callSigns && callSigns.length > 0;
  }

  private isDynamicObjectAssignedToStdType(lhsType: ts.Type, rhsExpr: ts.Expression): boolean {
    if (isStdLibraryType(lhsType) || this.isPrimitiveType(lhsType)) {
      let rhsSym = ts.isCallExpression(rhsExpr)
        ? this.getSymbolOfCallExpression(rhsExpr)
        : this.trueSymbolAtLocation(rhsExpr);
      if (rhsSym && this.isLibrarySymbol(rhsSym))
        return true;
    }
    return false;
  }

  validateFields(objectType: ts.Type, objectLiteral: ts.ObjectLiteralExpression): boolean {
    for (const prop of objectLiteral.properties) {
      if (ts.isPropertyAssignment(prop)) {
        if (!this.validateField(objectType, prop)) {
          return false;
        }
      }
    };

    return true;
  }

  private validateField(type: ts.Type, prop: ts.PropertyAssignment): boolean {
    const propName = prop.name.getText();
    const propSym = this.findProperty(type, propName);
    if (!propSym || !propSym.declarations?.length) {
      return false;
    }

    const propType = this.tsTypeChecker.getTypeOfSymbolAtLocation(propSym, propSym.declarations[0]);
    const initExpr = this.unwrapParenthesized(prop.initializer);
    if (ts.isObjectLiteralExpression(initExpr)) {
      if (!this.isObjectLiteralAssignable(propType, initExpr)) {
        return false;
      } 
    } else {
      // Only check for structural sub-typing.
      if (this.needToDeduceStructuralIdentity(propType, this.tsTypeChecker.getTypeAtLocation(initExpr), initExpr)) {
        return false;
      }
    }

    return true;
  }

  validateRecordObjectKeys(objectLiteral: ts.ObjectLiteralExpression): boolean {
    for (const prop of objectLiteral.properties) {
      if (!prop.name || (!ts.isStringLiteral(prop.name) && !ts.isNumericLiteral(prop.name))) return false;
    }
    return true;
  }

  getTargetType(type: ts.Type): ts.Type {
    return (type.getFlags() & ts.TypeFlags.Object) &&
    (type as ts.ObjectType).objectFlags & ts.ObjectFlags.Reference ? (type as ts.TypeReference).target : type;
  }

  private isSupportedTypeNodeKind(kind: ts.SyntaxKind): boolean {
    return kind !== ts.SyntaxKind.AnyKeyword && kind !== ts.SyntaxKind.UnknownKeyword &&
      kind !== ts.SyntaxKind.SymbolKeyword && kind !== ts.SyntaxKind.IndexedAccessType &&
      kind !== ts.SyntaxKind.ConditionalType && kind !== ts.SyntaxKind.MappedType &&
      kind !== ts.SyntaxKind.InferType;
  }

  public isSupportedType(typeNode: ts.TypeNode): boolean {
    if (ts.isParenthesizedTypeNode(typeNode)) return this.isSupportedType(typeNode.type);

    if (ts.isArrayTypeNode(typeNode)) return this.isSupportedType(typeNode.elementType);

    if (ts.isTypeReferenceNode(typeNode) && typeNode.typeArguments) {
      for (const typeArg of typeNode.typeArguments)
        if (!this.isSupportedType(typeArg)) return false;
      return true;
    }

    if (ts.isUnionTypeNode(typeNode)) {
      for (const unionTypeElem of typeNode.types)
        if (!this.isSupportedType(unionTypeElem)) return false;
      return true;
    }

    if (ts.isTupleTypeNode(typeNode)) {
      for (const elem of typeNode.elements) {
        if (ts.isTypeNode(elem) && !this.isSupportedType(elem)) return false;
        if (ts.isNamedTupleMember(elem) && !this.isSupportedType(elem.type)) return false;
      }
      return true;
    }

    return !ts.isTypeLiteralNode(typeNode) && (this.advancedClassChecks || !ts.isTypeQueryNode(typeNode)) &&
      !ts.isIntersectionTypeNode(typeNode) && this.isSupportedTypeNodeKind(typeNode.kind);
  }

  public isStructObjectInitializer(objectLiteral: ts.ObjectLiteralExpression): boolean {
    if (ts.isCallLikeExpression(objectLiteral.parent)) {
      const signature = this.tsTypeChecker.getResolvedSignature(objectLiteral.parent);
      const signDecl = signature?.declaration;
      return !!signDecl && ts.isConstructorDeclaration(signDecl) && isStructDeclaration(signDecl.parent);
    }
    return false;
  }

  public getParentSymbolName(symbol: ts.Symbol): string | undefined {
    const name = this.tsTypeChecker.getFullyQualifiedName(symbol);
    const dotPosition = name.lastIndexOf('.');
    return (dotPosition === -1) ? undefined : name.substring(0, dotPosition);
  }

  public isGlobalSymbol(symbol: ts.Symbol): boolean {
    let parentName = this.getParentSymbolName(symbol);
    return !parentName || parentName === 'global';
  }

  public isStdObjectAPI(symbol: ts.Symbol): boolean {
    let parentName = this.getParentSymbolName(symbol);
    return !!parentName && (parentName === 'Object');
  }

  public isStdReflectAPI(symbol: ts.Symbol): boolean {
    let parentName = this.getParentSymbolName(symbol);
    return !!parentName && (parentName === 'Reflect');
  }

  public isStdProxyHandlerAPI(symbol: ts.Symbol): boolean {
    let parentName = this.getParentSymbolName(symbol);
    return !!parentName && (parentName === 'ProxyHandler');
  }

  public isStdArrayAPI(symbol: ts.Symbol): boolean {
    let parentName = this.getParentSymbolName(symbol);
    return !!parentName && (parentName === 'Array');
  }

  public isStdArrayBufferAPI(symbol: ts.Symbol): boolean {
    let parentName = this.getParentSymbolName(symbol);
    return !!parentName && (parentName === 'ArrayBuffer');
  }

  public isStdSymbol(symbol: ts.Symbol): boolean {
    const name = this.tsTypeChecker.getFullyQualifiedName(symbol)
    return name === 'Symbol';
  }

  public isStdSymbolAPI(symbol: ts.Symbol): boolean {
    let parentName = this.getParentSymbolName(symbol);
    return !!parentName && (parentName === 'Symbol');
  }

  public isDefaultImport(importSpec: ts.ImportSpecifier): boolean {
    return importSpec?.propertyName?.text === 'default';
  }

  public getStartPos(nodeOrComment: ts.Node | ts.CommentRange): number {
    return (nodeOrComment.kind === ts.SyntaxKind.SingleLineCommentTrivia || nodeOrComment.kind === ts.SyntaxKind.MultiLineCommentTrivia)
      ? (nodeOrComment as ts.CommentRange).pos
      : (nodeOrComment as ts.Node).getStart();
  }

  public getEndPos(nodeOrComment: ts.Node | ts.CommentRange): number {
    return (nodeOrComment.kind === ts.SyntaxKind.SingleLineCommentTrivia || nodeOrComment.kind === ts.SyntaxKind.MultiLineCommentTrivia)
      ? (nodeOrComment as ts.CommentRange).end
      : (nodeOrComment as ts.Node).getEnd();
  }

  public isStdRecordType(type: ts.Type): boolean {
    // In TypeScript, 'Record<K, T>' is defined as type alias to a mapped type.
    // Thus, it should have 'aliasSymbol' and 'target' properties. The 'target'
    // in this case will resolve to origin 'Record' symbol.
    if (type.aliasSymbol) {
      const target = (type as ts.TypeReference).target;
      if (target) {
        const sym = target.aliasSymbol;
        return !!sym && sym.getName() === 'Record' && this.isGlobalSymbol(sym);
      }
    }

    return false;
  }

  public isStdPartialType(type: ts.Type): boolean {
    const sym = type.aliasSymbol;
    return !!sym && sym.getName() === 'Partial' && this.isGlobalSymbol(sym);
  }

  public isStdRequiredType(type: ts.Type): boolean {
    const sym = type.aliasSymbol;
    return !!sym && sym.getName() === 'Required' && this.isGlobalSymbol(sym);
  }
  
  public isStdReadonlyType(type: ts.Type): boolean {
    const sym = type.aliasSymbol;
    return !!sym && sym.getName() === 'Readonly' && this.isGlobalSymbol(sym);
  }

  public isLibraryType(type: ts.Type): boolean {
    const nonNullableType = type.getNonNullableType();
    if (nonNullableType.isUnion()) {
      for (const componentType of nonNullableType.types) {
        if (!this.isLibraryType(componentType)) {
          return false;
        }
      }
      return true;
    }
    return this.isLibrarySymbol(nonNullableType.aliasSymbol ?? nonNullableType.getSymbol());
  }

  public hasLibraryType(node: ts.Node): boolean {
    return this.isLibraryType(this.tsTypeChecker.getTypeAtLocation(node));
  }

  public isLibrarySymbol(sym: ts.Symbol | undefined): boolean {
    if (sym && sym.declarations && sym.declarations.length > 0) {
      const srcFile = sym.declarations[0].getSourceFile();
      if (!srcFile) {
        return false;
      }
      const fileName = srcFile.fileName
      // Symbols from both *.ts and *.d.ts files should obey interop rules.
      // We disable such behavior for *.ts files in the test mode due to lack of 'ets'
      // extension support.
      const ext = path.extname(fileName).toLowerCase();
      const isThirdPartyCode =
        ARKTS_IGNORE_DIRS.some(ignore => pathContainsDirectory(path.normalize(fileName), ignore)) ||
        ARKTS_IGNORE_FILES.some(ignore => path.basename(fileName) === ignore);
      const isEts = (ext === '.ets');
      const isTs = (ext === '.ts' && !srcFile.isDeclarationFile);
      const isStatic = (isEts || (isTs && this.testMode)) && !isThirdPartyCode;
      // We still need to confirm support for certain API from the
      // TypeScript standard library in ArkTS. Thus, for now do not
      // count standard library modules.
      return !isStatic &&
        !STANDARD_LIBRARIES.includes(path.basename(fileName).toLowerCase());
    }
    return false;
  }

  public isStdFunctionType(type: ts.Type) {
    const sym = type.getSymbol();
    return sym && sym.getName() === 'Function' && this.isGlobalSymbol(sym);
  }

  public isDynamicType(type: ts.Type | undefined): boolean | undefined {
    if (type === undefined) {
      return false;
    }

    // Return 'true' if it is an object of library type initialization, otherwise
    // return 'false' if it is not an object of standard library type one.
    // In the case of standard library type we need to determine context.

    // Check the non-nullable version of type to eliminate 'undefined' type
    // from the union type elements.
    type = type.getNonNullableType();

    if (type.isUnion()) {
      for (let compType of type.types) {
        let isDynamic = this.isDynamicType(compType); 
        if (isDynamic || isDynamic === undefined) {
          return isDynamic;
        }
      }
      return false;
    }

    if (this.isLibraryType(type)) {
      return true;
    }

    if (!isStdLibraryType(type) && !isIntrinsicObjectType(type) && !this.isAnyType(type)) {
      return false;
    }

    return undefined;
  }

  public isObjectType(type: ts.Type): type is ts.ObjectType {
    return !!(type.flags & ts.TypeFlags.Object)
  }

  private isAnonymous(type: ts.Type): boolean {
    if (this.isObjectType(type)) {
      return !!(type.objectFlags & ts.ObjectFlags.Anonymous);
    }
    return false;
  }

  public isDynamicLiteralInitializer(expr: ts.Expression): boolean {
    if (!ts.isObjectLiteralExpression(expr) && !ts.isArrayLiteralExpression(expr)) {
      return false;
    }

    // Handle nested literals:
    // { f: { ... } }
    let curNode: ts.Node = expr;
    while (ts.isObjectLiteralExpression(curNode) || ts.isArrayLiteralExpression(curNode)) {
      const exprType = this.tsTypeChecker.getContextualType(curNode);
      if (exprType !== undefined && !this.isAnonymous(exprType)) {
        const res = this.isDynamicType(exprType)
        if (res !== undefined) {
          return res;
        }
      }

      curNode = curNode.parent;
      if (ts.isPropertyAssignment(curNode)) {
        curNode = curNode.parent;
      }
    }

    // Handle calls with literals:
    // foo({ ... })
    if (ts.isCallExpression(curNode)) {
      const callExpr = curNode as ts.CallExpression;
      const type = this.tsTypeChecker.getTypeAtLocation(callExpr.expression)

      if (this.isAnyType(type)) {
        return true;
      }

      let sym: ts.Symbol | undefined = type.symbol;
      if(this.isLibrarySymbol(sym)) {
        return true;
      }

      // #13483:
      // x.foo({ ... }), where 'x' is exported from some library:
      if (ts.isPropertyAccessExpression(callExpr.expression)) {
        sym = this.trueSymbolAtLocation(callExpr.expression.expression);
        if (sym && this.isLibrarySymbol(sym)) {
          return true;
        }
      }
    }

    // Handle property assignments with literals:
    // obj.f = { ... }
    if (ts.isBinaryExpression(curNode)) {
      const binExpr = curNode as ts.BinaryExpression;
      if (ts.isPropertyAccessExpression(binExpr.left)) {
        const propAccessExpr = binExpr.left as ts.PropertyAccessExpression;
        const type = this.tsTypeChecker.getTypeAtLocation(propAccessExpr.expression);
        return this.isLibrarySymbol(type.symbol);
      }
    }

    return false;
  }

  public isEsObjectType(typeNode: ts.TypeNode): boolean {
    return ts.isTypeReferenceNode(typeNode) && ts.isIdentifier(typeNode.typeName) &&
      typeNode.typeName.text == ES_OBJECT;
  }

  public isInsideBlock(node: ts.Node): boolean {
    let par = node.parent
    while (par) {
      if (ts.isBlock(par)) {
        return true;
      }
      par = par.parent;
    }
    return false;
  }

  public isEsObjectPossiblyAllowed(typeRef: ts.TypeReferenceNode): boolean {
    return ts.isVariableDeclaration(typeRef.parent);
  }

  public isValueAssignableToESObject(node: ts.Node): boolean {
    if (ts.isArrayLiteralExpression(node) || ts.isObjectLiteralExpression(node)) {
      return false;
    }
    const valueType = this.tsTypeChecker.getTypeAtLocation(node);
    return this.isUnsupportedType(valueType) || this.isAnonymousType(valueType)
  }

  public getVariableDeclarationTypeNode(node: ts.Node): ts.TypeNode | undefined {
    let sym = this.trueSymbolAtLocation(node);
    if (sym === undefined) {
      return undefined;
    }
    return this.getSymbolDeclarationTypeNode(sym);
  }

  public getSymbolDeclarationTypeNode(sym: ts.Symbol): ts.TypeNode | undefined {
    const decl = this.getDeclaration(sym);
    if (!!decl && ts.isVariableDeclaration(decl)) {
      return decl.type;
    }
    return undefined;
  }

  public hasEsObjectType(node: ts.Node): boolean {
    const typeNode = this.getVariableDeclarationTypeNode(node)
    return typeNode !== undefined && this.isEsObjectType(typeNode);
  }

  public symbolHasEsObjectType(sym: ts.Symbol): boolean {
    const typeNode = this.getSymbolDeclarationTypeNode(sym);
    return typeNode !== undefined && this.isEsObjectType(typeNode);
  }

  public isEsObjectSymbol(sym: ts.Symbol): boolean {
    let decl = this.getDeclaration(sym);
    return !!decl && ts.isTypeAliasDeclaration(decl) && decl.name.escapedText == ES_OBJECT &&
      decl.type.kind === ts.SyntaxKind.AnyKeyword;
  }

  public isAnonymousType(type: ts.Type): boolean {
    if (type.isUnionOrIntersection()) {
      for (let compType of type.types) {
        if (this.isAnonymousType(compType)) {
          return true;
        }
      }
      return false;
    }

    return (type.flags & ts.TypeFlags.Object) !== 0 &&
      ((type as ts.ObjectType).objectFlags & ts.ObjectFlags.Anonymous) !== 0;
  }

  public getSymbolOfCallExpression(callExpr: ts.CallExpression): ts.Symbol | undefined {
    const signature = this.tsTypeChecker.getResolvedSignature(callExpr);
    const signDecl = signature?.getDeclaration();
    if (signDecl && signDecl.name) {
      return this.trueSymbolAtLocation(signDecl.name);
    }
    return undefined;
  }

  // has to be re-implemented with local loop detection
  public typeIsRecursive(topType: ts.Type, type: ts.Type | undefined = undefined): boolean {
    if (type == undefined) {
      type = topType;
    } else if (type == topType) {
      return true;
    } else if (type.aliasSymbol) {
      return false;
    }

    if (type.isUnion()) {
      for (let unionElem of type.types) {
        if (this.typeIsRecursive(topType, unionElem)) {
          return true;
        }
      }
    }
    if (type.flags & ts.TypeFlags.Object && (type as ts.ObjectType).objectFlags & ts.ObjectFlags.Reference) {
      const typeArgs = this.tsTypeChecker.getTypeArguments(type as ts.TypeReference);
      if (typeArgs) {
        for (const typeArg of typeArgs) {
          if (this.typeIsRecursive(topType, typeArg)) {
            return true;
          }
        }
      }
    }
    return false;
  }

  public isClassValueType(type: ts.Type): boolean {
    if ((type.flags & ts.TypeFlags.Object) === 0 || ((type as ts.ObjectType).objectFlags & ts.ObjectFlags.Anonymous) === 0) {
      return false;
    }
    return type.symbol && (type.symbol.flags & ts.SymbolFlags.Class) !== 0;
  }

  public isClassObjectExpression(expr: ts.Expression): boolean {
    if (!this.isClassValueType(this.tsTypeChecker.getTypeAtLocation(expr))) {
      return false;
    }
    let symbol = this.trueSymbolAtLocation(expr);
    return !symbol || (symbol.flags & ts.SymbolFlags.Class) === 0;
  }

  public isClassTypeExrepssion(expr: ts.Expression): boolean {
    let sym = this.trueSymbolAtLocation(expr);
    return sym !== undefined && (sym.flags & ts.SymbolFlags.Class) !== 0;
  }

  public isFunctionCalledRecursively(funcExpr: ts.FunctionExpression): boolean {
    if (!funcExpr.name) return false;

    const sym = this.tsTypeChecker.getSymbolAtLocation(funcExpr.name);
    if (!sym) return false;

    let found = false;
    const self = this;
    function visitNode(tsNode: ts.Node) {
      // Stop visiting child nodes if finished searching.
      if (found) {
        return;
      }

      if (ts.isCallExpression(tsNode) && ts.isIdentifier(tsNode.expression)) {
        const callSym = self.tsTypeChecker.getSymbolAtLocation(tsNode.expression);
        if (callSym && callSym === sym) {
          found = true;
          return;
        }
      }

      // Visit children nodes.
      tsNode.forEachChild(visitNode);
    }

    visitNode(funcExpr);
    return found;
  }
}
