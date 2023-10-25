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
import { FaultID } from './Problems';

export class LinterConfig {
  static nodeDesc: string[] = [];

  // The SyntaxKind enum defines additional elements at the end of the enum
  // that serve as markers (FirstX/LastX). Those elements are initialized
  // with indices of the previously defined elements. As result, the enum
  // may return incorrect name for a certain kind index (e.g. 'FirstStatement'
  // instead of 'VariableStatement').
  // The following code creates a map with correct syntax kind names.
  // It can be used when need to print name of syntax kind of certain
  // AST node in diagnostic messages.
  static tsSyntaxKindNames: string[] = [];

  // Use static init method, as TypeScript 4.2 doesn't support static blocks.
  static initStatic() {
    // Set the feature descriptions (for the output).
    LinterConfig.nodeDesc[FaultID.AnyType] = '"any" type';
    LinterConfig.nodeDesc[FaultID.SymbolType] = '"symbol" type';
    LinterConfig.nodeDesc[FaultID.ObjectLiteralNoContextType] = 'Object literals with no context Class or Interface type';
    LinterConfig.nodeDesc[FaultID.ArrayLiteralNoContextType] = 'Array literals with no context Array type';
    LinterConfig.nodeDesc[FaultID.ComputedPropertyName] = 'Computed properties';
    LinterConfig.nodeDesc[FaultID.LiteralAsPropertyName] = 'String or integer literal as property name';
    LinterConfig.nodeDesc[FaultID.TypeQuery] = '"typeof" operations';
    LinterConfig.nodeDesc[FaultID.RegexLiteral] = 'regex literals';
    LinterConfig.nodeDesc[FaultID.IsOperator] = '"is" operations';
    LinterConfig.nodeDesc[FaultID.DestructuringParameter] = 'destructuring parameters';
    LinterConfig.nodeDesc[FaultID.YieldExpression] = '"yield" operations';
    LinterConfig.nodeDesc[FaultID.InterfaceMerging] = 'merging interfaces';
    LinterConfig.nodeDesc[FaultID.EnumMerging] = 'merging enums';
    LinterConfig.nodeDesc[FaultID.InterfaceExtendsClass] = 'interfaces inherited from classes';
    LinterConfig.nodeDesc[FaultID.IndexMember] = 'index members';
    LinterConfig.nodeDesc[FaultID.WithStatement] = '"with" statements';
    LinterConfig.nodeDesc[FaultID.ThrowStatement] = '"throw" statements with expression of wrong type';
    LinterConfig.nodeDesc[FaultID.IndexedAccessType] = 'Indexed access type';
    LinterConfig.nodeDesc[FaultID.UnknownType] = '"unknown" type';
    LinterConfig.nodeDesc[FaultID.ForInStatement] = '"for-In" statements';
    LinterConfig.nodeDesc[FaultID.InOperator] = '"in" operations';
    LinterConfig.nodeDesc[FaultID.ImportFromPath] = 'imports from path';
    LinterConfig.nodeDesc[FaultID.FunctionExpression] = 'function expressions';
    LinterConfig.nodeDesc[FaultID.IntersectionType] = 'intersection types and type literals';
    LinterConfig.nodeDesc[FaultID.ObjectTypeLiteral] = 'Object type literals';
    // LinterConfig.nodeDesc[FaultID.BitOpWithWrongType] = 'bit operation with wrong operand';
    LinterConfig.nodeDesc[FaultID.CommaOperator] = 'comma operator';
    LinterConfig.nodeDesc[FaultID.LimitedReturnTypeInference] = 'Functions with limited return type inference';
    LinterConfig.nodeDesc[FaultID.LambdaWithTypeParameters] = 'Lambda function with type parameters';
    LinterConfig.nodeDesc[FaultID.ClassExpression] = 'Class expressions';
    LinterConfig.nodeDesc[FaultID.DestructuringAssignment] = 'Destructuring assignments';
    LinterConfig.nodeDesc[FaultID.DestructuringDeclaration] = 'Destructuring variable declarations';
    LinterConfig.nodeDesc[FaultID.VarDeclaration] = '"var" declarations';
    LinterConfig.nodeDesc[FaultID.CatchWithUnsupportedType] = '"catch" clause with unsupported exception type';
    LinterConfig.nodeDesc[FaultID.DeleteOperator] = '"delete" operations';
    LinterConfig.nodeDesc[FaultID.DeclWithDuplicateName] = 'Declarations with duplicate name';
    LinterConfig.nodeDesc[FaultID.UnaryArithmNotNumber] = 'Unary arithmetics with not-numeric values';
    LinterConfig.nodeDesc[FaultID.ConstructorType] = 'Constructor type';
    LinterConfig.nodeDesc[FaultID.ConstructorFuncs] = 'Constructor function type is not supported';
    LinterConfig.nodeDesc[FaultID.ConstructorIface] = 'Construct signatures are not supported in interfaces';
    LinterConfig.nodeDesc[FaultID.CallSignature] = 'Call signatures';
    LinterConfig.nodeDesc[FaultID.TypeAssertion] = 'Type assertion expressions';
    LinterConfig.nodeDesc[FaultID.PrivateIdentifier] = 'Private identifiers (with "#" prefix)';
    LinterConfig.nodeDesc[FaultID.LocalFunction] = 'Local function declarations';
    LinterConfig.nodeDesc[FaultID.ConditionalType] = 'Conditional type';
    LinterConfig.nodeDesc[FaultID.MappedType] = 'Mapped type';
    LinterConfig.nodeDesc[FaultID.NamespaceAsObject] = 'Namespaces used as objects';
    LinterConfig.nodeDesc[FaultID.ClassAsObject] = 'Class used as object';
    LinterConfig.nodeDesc[FaultID.NonDeclarationInNamespace] = 'Non-declaration statements in namespaces';
    LinterConfig.nodeDesc[FaultID.GeneratorFunction] = 'Generator functions';
    LinterConfig.nodeDesc[FaultID.FunctionContainsThis] = 'Functions containing "this"';
    LinterConfig.nodeDesc[FaultID.PropertyAccessByIndex] = 'property access by index';
    LinterConfig.nodeDesc[FaultID.JsxElement] = 'JSX Elements';
    LinterConfig.nodeDesc[FaultID.EnumMemberNonConstInit] = 'Enum members with non-constant initializer';
    LinterConfig.nodeDesc[FaultID.ImplementsClass] = 'Class type mentioned in "implements" clause';
    LinterConfig.nodeDesc[FaultID.MethodReassignment] = 'Access to undefined field';
    LinterConfig.nodeDesc[FaultID.MultipleStaticBlocks] = 'Multiple static blocks';
    LinterConfig.nodeDesc[FaultID.ThisType] = '"this" type';
    LinterConfig.nodeDesc[FaultID.IntefaceExtendDifProps] = 'Extends same properties with different types';
    LinterConfig.nodeDesc[FaultID.StructuralIdentity] = 'Use of type structural identity';
    LinterConfig.nodeDesc[FaultID.TypeOnlyImport] = 'Type-only imports';
    LinterConfig.nodeDesc[FaultID.TypeOnlyExport] = 'Type-only exports';
    LinterConfig.nodeDesc[FaultID.DefaultImport] = 'Default import declarations';
    LinterConfig.nodeDesc[FaultID.ExportAssignment] = 'Export assignments (export = ..)';
    LinterConfig.nodeDesc[FaultID.ImportAssignment] = 'Import assignments (import = ..)';
    LinterConfig.nodeDesc[FaultID.GenericCallNoTypeArgs] = 'Generic calls without type arguments';
    LinterConfig.nodeDesc[FaultID.ParameterProperties] = 'Parameter properties in constructor';
    LinterConfig.nodeDesc[FaultID.InstanceofUnsupported] = 'Left-hand side of "instanceof" is wrong';
    LinterConfig.nodeDesc[FaultID.ShorthandAmbientModuleDecl] = 'Shorthand ambient module declaration';
    LinterConfig.nodeDesc[FaultID.WildcardsInModuleName] = 'Wildcards in module name';
    LinterConfig.nodeDesc[FaultID.UMDModuleDefinition] = 'UMD module definition';
    LinterConfig.nodeDesc[FaultID.NewTarget] = '"new.target" meta-property';
    LinterConfig.nodeDesc[FaultID.DefiniteAssignment] = 'Definite assignment assertion';
    LinterConfig.nodeDesc[FaultID.Prototype] = 'Prototype assignment';
    LinterConfig.nodeDesc[FaultID.GlobalThis] = 'Use of globalThis';
    LinterConfig.nodeDesc[FaultID.UtilityType] = 'Standard Utility types';
    LinterConfig.nodeDesc[FaultID.PropertyDeclOnFunction] = 'Property declaration on function';
    LinterConfig.nodeDesc[FaultID.FunctionApplyBindCall] = 'Invoking methods of function objects';
    LinterConfig.nodeDesc[FaultID.ConstAssertion] = '"as const" assertion';
    LinterConfig.nodeDesc[FaultID.ImportAssertion] = 'Import assertion';
    LinterConfig.nodeDesc[FaultID.SpreadOperator] = 'Spread operation';
    LinterConfig.nodeDesc[FaultID.LimitedStdLibApi] = 'Limited standard library API';
    LinterConfig.nodeDesc[FaultID.ErrorSuppression] = 'Error suppression annotation';
    LinterConfig.nodeDesc[FaultID.StrictDiagnostic] = 'Strict diagnostic';
    LinterConfig.nodeDesc[FaultID.UnsupportedDecorators] = 'Unsupported decorators';
    LinterConfig.nodeDesc[FaultID.ImportAfterStatement] = 'Import declaration after other declaration or statement';
    LinterConfig.nodeDesc[FaultID.EsObjectType] = 'Restricted "ESObject" type';

    LinterConfig.initTsSyntaxKindNames();
  }

  private static initTsSyntaxKindNames(): void {
    const keys = Object.keys(ts.SyntaxKind);
    const values = Object.values(ts.SyntaxKind);

    for (let i = 0; i < values.length; i++) {
      const val = values[i];
      const kindNum = typeof val === 'string' ? parseInt(val) : val;
      if (kindNum && !LinterConfig.tsSyntaxKindNames[kindNum]) {
        LinterConfig.tsSyntaxKindNames[kindNum] = keys[i];
      }
    }
  }

  // must detect terminals during parsing
  static terminalTokens: Set<ts.SyntaxKind> = new Set([
    ts.SyntaxKind.OpenBraceToken, ts.SyntaxKind.CloseBraceToken, ts.SyntaxKind.OpenParenToken, 
    ts.SyntaxKind.CloseParenToken, ts.SyntaxKind.OpenBracketToken, ts.SyntaxKind.CloseBracketToken,
    ts.SyntaxKind.DotToken, ts.SyntaxKind.DotDotDotToken, ts.SyntaxKind.SemicolonToken, ts.SyntaxKind.CommaToken,
    ts.SyntaxKind.QuestionDotToken, ts.SyntaxKind.LessThanToken, ts.SyntaxKind.LessThanSlashToken,
    ts.SyntaxKind.GreaterThanToken, ts.SyntaxKind.LessThanEqualsToken, ts.SyntaxKind.GreaterThanEqualsToken,
    ts.SyntaxKind.EqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsToken, ts.SyntaxKind.EqualsEqualsEqualsToken,
    ts.SyntaxKind.ExclamationEqualsEqualsToken, ts.SyntaxKind.EqualsGreaterThanToken, ts.SyntaxKind.PlusToken,
    ts.SyntaxKind.MinusToken, ts.SyntaxKind.AsteriskToken, ts.SyntaxKind.AsteriskAsteriskToken,
    ts.SyntaxKind.SlashToken, ts.SyntaxKind.PercentToken, ts.SyntaxKind.PlusPlusToken, ts.SyntaxKind.MinusMinusToken,
    ts.SyntaxKind.LessThanLessThanToken, ts.SyntaxKind.GreaterThanGreaterThanToken,
    ts.SyntaxKind.GreaterThanGreaterThanGreaterThanToken, ts.SyntaxKind.AmpersandToken, ts.SyntaxKind.BarToken,
    ts.SyntaxKind.CaretToken, ts.SyntaxKind.ExclamationToken, ts.SyntaxKind.TildeToken,
    ts.SyntaxKind.AmpersandAmpersandToken, ts.SyntaxKind.BarBarToken, ts.SyntaxKind.QuestionQuestionToken,
    ts.SyntaxKind.QuestionToken, ts.SyntaxKind.ColonToken, ts.SyntaxKind.AtToken, ts.SyntaxKind.BacktickToken,
    ts.SyntaxKind.EqualsToken, ts.SyntaxKind.PlusEqualsToken, ts.SyntaxKind.MinusEqualsToken,
    ts.SyntaxKind.AsteriskEqualsToken, ts.SyntaxKind.AsteriskAsteriskEqualsToken, ts.SyntaxKind.SlashEqualsToken,
    ts.SyntaxKind.PercentEqualsToken, ts.SyntaxKind.LessThanLessThanEqualsToken,
    ts.SyntaxKind.GreaterThanGreaterThanEqualsToken, ts.SyntaxKind.GreaterThanGreaterThanGreaterThanEqualsToken,
    ts.SyntaxKind.AmpersandEqualsToken, ts.SyntaxKind.BarEqualsToken, ts.SyntaxKind.CaretEqualsToken,
    ts.SyntaxKind.EndOfFileToken, ts.SyntaxKind.SingleLineCommentTrivia,
    ts.SyntaxKind.MultiLineCommentTrivia, ts.SyntaxKind.NewLineTrivia, ts.SyntaxKind.WhitespaceTrivia,
    ts.SyntaxKind.ShebangTrivia, /* We detect and preserve #! on the first line */ ts.SyntaxKind.ConflictMarkerTrivia,
  ]);

  // tokens which can be reported without additional parsing
  static incrementOnlyTokens: Map<ts.SyntaxKind, FaultID> = new Map([
    [ts.SyntaxKind.AnyKeyword, FaultID.AnyType], [ts.SyntaxKind.SymbolKeyword, FaultID.SymbolType],
    [ts.SyntaxKind.ThisType, FaultID.ThisType],
    [ts.SyntaxKind.ComputedPropertyName, FaultID.ComputedPropertyName],
    [ts.SyntaxKind.TypeQuery, FaultID.TypeQuery],
    [ts.SyntaxKind.DeleteExpression, FaultID.DeleteOperator],
    [ts.SyntaxKind.RegularExpressionLiteral, FaultID.RegexLiteral],
    [ts.SyntaxKind.TypePredicate, FaultID.IsOperator], [ts.SyntaxKind.YieldExpression, FaultID.YieldExpression],
    [ts.SyntaxKind.IndexSignature, FaultID.IndexMember], [ts.SyntaxKind.WithStatement, FaultID.WithStatement],
    [ts.SyntaxKind.IndexedAccessType, FaultID.IndexedAccessType],[ts.SyntaxKind.UnknownKeyword, FaultID.UnknownType],
    [ts.SyntaxKind.InKeyword, FaultID.InOperator], [ts.SyntaxKind.CallSignature, FaultID.CallSignature],
    [ts.SyntaxKind.IntersectionType, FaultID.IntersectionType],
    [ts.SyntaxKind.TypeLiteral, FaultID.ObjectTypeLiteral], [ts.SyntaxKind.ConstructorType, FaultID.ConstructorFuncs],
    [ts.SyntaxKind.PrivateIdentifier, FaultID.PrivateIdentifier],
    [ts.SyntaxKind.ConditionalType, FaultID.ConditionalType], [ts.SyntaxKind.MappedType, FaultID.MappedType],
    [ts.SyntaxKind.JsxElement, FaultID.JsxElement], [ts.SyntaxKind.JsxSelfClosingElement, FaultID.JsxElement],
    [ts.SyntaxKind.ImportEqualsDeclaration, FaultID.ImportAssignment],
    [ts.SyntaxKind.NamespaceExportDeclaration, FaultID.UMDModuleDefinition],
  ]);
}
