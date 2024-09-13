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

import { FaultID } from './Problems';

export const faultDesc: string[] = [];

faultDesc[FaultID.AnyType] = '"any" type';
faultDesc[FaultID.SymbolType] = '"symbol" type';
faultDesc[FaultID.ObjectLiteralNoContextType] = 'Object literals with no context Class or Interface type';
faultDesc[FaultID.ArrayLiteralNoContextType] = 'Array literals with no context Array type';
faultDesc[FaultID.ComputedPropertyName] = 'Computed properties';
faultDesc[FaultID.LiteralAsPropertyName] = 'String or integer literal as property name';
faultDesc[FaultID.TypeQuery] = '"typeof" operations';
faultDesc[FaultID.IsOperator] = '"is" operations';
faultDesc[FaultID.DestructuringParameter] = 'destructuring parameters';
faultDesc[FaultID.YieldExpression] = '"yield" operations';
faultDesc[FaultID.InterfaceMerging] = 'merging interfaces';
faultDesc[FaultID.EnumMerging] = 'merging enums';
faultDesc[FaultID.InterfaceExtendsClass] = 'interfaces inherited from classes';
faultDesc[FaultID.IndexMember] = 'index members';
faultDesc[FaultID.WithStatement] = '"with" statements';
faultDesc[FaultID.ThrowStatement] = '"throw" statements with expression of wrong type';
faultDesc[FaultID.IndexedAccessType] = 'Indexed access type';
faultDesc[FaultID.UnknownType] = '"unknown" type';
faultDesc[FaultID.ForInStatement] = '"for-In" statements';
faultDesc[FaultID.InOperator] = '"in" operations';
faultDesc[FaultID.FunctionExpression] = 'function expressions';
faultDesc[FaultID.IntersectionType] = 'intersection types and type literals';
faultDesc[FaultID.ObjectTypeLiteral] = 'Object type literals';
faultDesc[FaultID.CommaOperator] = 'comma operator';
faultDesc[FaultID.LimitedReturnTypeInference] = 'Functions with limited return type inference';
faultDesc[FaultID.ClassExpression] = 'Class expressions';
faultDesc[FaultID.DestructuringAssignment] = 'Destructuring assignments';
faultDesc[FaultID.DestructuringDeclaration] = 'Destructuring variable declarations';
faultDesc[FaultID.VarDeclaration] = '"var" declarations';
faultDesc[FaultID.CatchWithUnsupportedType] = '"catch" clause with unsupported exception type';
faultDesc[FaultID.DeleteOperator] = '"delete" operations';
faultDesc[FaultID.DeclWithDuplicateName] = 'Declarations with duplicate name';
faultDesc[FaultID.UnaryArithmNotNumber] = 'Unary arithmetics with not-numeric values';
faultDesc[FaultID.ConstructorType] = 'Constructor type';
faultDesc[FaultID.ConstructorFuncs] = 'Constructor function type is not supported';
faultDesc[FaultID.ConstructorIface] = 'Construct signatures are not supported in interfaces';
faultDesc[FaultID.CallSignature] = 'Call signatures';
faultDesc[FaultID.TypeAssertion] = 'Type assertion expressions';
faultDesc[FaultID.PrivateIdentifier] = 'Private identifiers (with "#" prefix)';
faultDesc[FaultID.LocalFunction] = 'Local function declarations';
faultDesc[FaultID.ConditionalType] = 'Conditional type';
faultDesc[FaultID.MappedType] = 'Mapped type';
faultDesc[FaultID.NamespaceAsObject] = 'Namespaces used as objects';
faultDesc[FaultID.ClassAsObject] = faultDesc[FaultID.ClassAsObjectError] = 'Class used as object';
faultDesc[FaultID.NonDeclarationInNamespace] = 'Non-declaration statements in namespaces';
faultDesc[FaultID.GeneratorFunction] = 'Generator functions';
faultDesc[FaultID.FunctionContainsThis] = 'Functions containing "this"';
faultDesc[FaultID.PropertyAccessByIndex] = 'property access by index';
faultDesc[FaultID.JsxElement] = 'JSX Elements';
faultDesc[FaultID.EnumMemberNonConstInit] = 'Enum members with non-constant initializer';
faultDesc[FaultID.ImplementsClass] = 'Class type mentioned in "implements" clause';
faultDesc[FaultID.MethodReassignment] = 'Access to undefined field';
faultDesc[FaultID.MultipleStaticBlocks] = 'Multiple static blocks';
faultDesc[FaultID.ThisType] = '"this" type';
faultDesc[FaultID.IntefaceExtendDifProps] = 'Extends same properties with different types';
faultDesc[FaultID.StructuralIdentity] = 'Use of type structural identity';
faultDesc[FaultID.ExportAssignment] = 'Export assignments (export = ..)';
faultDesc[FaultID.ImportAssignment] = 'Import assignments (import = ..)';
faultDesc[FaultID.GenericCallNoTypeArgs] = 'Generic calls without type arguments';
faultDesc[FaultID.ParameterProperties] = 'Parameter properties in constructor';
faultDesc[FaultID.InstanceofUnsupported] = 'Left-hand side of "instanceof" is wrong';
faultDesc[FaultID.ShorthandAmbientModuleDecl] = 'Shorthand ambient module declaration';
faultDesc[FaultID.WildcardsInModuleName] = 'Wildcards in module name';
faultDesc[FaultID.UMDModuleDefinition] = 'UMD module definition';
faultDesc[FaultID.NewTarget] = '"new.target" meta-property';
faultDesc[FaultID.DefiniteAssignment] = faultDesc[FaultID.DefiniteAssignmentError] = 'Definite assignment assertion';
faultDesc[FaultID.Prototype] = 'Prototype assignment';
faultDesc[FaultID.GlobalThis] = faultDesc[FaultID.GlobalThisError] = 'Use of globalThis';
faultDesc[FaultID.UtilityType] = 'Standard Utility types';
faultDesc[FaultID.PropertyDeclOnFunction] = 'Property declaration on function';
faultDesc[FaultID.FunctionApplyCall] = 'Invoking methods of function objects';
faultDesc[FaultID.FunctionBind] = faultDesc[FaultID.FunctionBindError] = 'Invoking methods of function objects';
faultDesc[FaultID.ConstAssertion] = '"as const" assertion';
faultDesc[FaultID.ImportAssertion] = 'Import assertion';
faultDesc[FaultID.SpreadOperator] = 'Spread operation';
faultDesc[FaultID.LimitedStdLibApi] = 'Limited standard library API';
faultDesc[FaultID.ErrorSuppression] = 'Error suppression annotation';
faultDesc[FaultID.StrictDiagnostic] = 'Strict diagnostic';
faultDesc[FaultID.ImportAfterStatement] = 'Import declaration after other declaration or statement';
faultDesc[FaultID.EsObjectType] = faultDesc[FaultID.EsObjectTypeError] = 'Restricted "ESObject" type';
faultDesc[FaultID.SendableClassInheritance] = 'Sendable class inheritance';
faultDesc[FaultID.SendablePropType] = 'Sendable class property';
faultDesc[FaultID.SendableDefiniteAssignment] = 'Use of definite assignment assertion in "Sendable" class';
faultDesc[FaultID.SendableGenericTypes] = 'Sendable generic types';
faultDesc[FaultID.SendableCapturedVars] = 'Sendable class captured variables';
faultDesc[FaultID.SendableClassDecorator] = 'Sendable class decorator';
faultDesc[FaultID.SendableObjectInitialization] =
  'Object literal or array literal is not allowed to initialize a "Sendable" object';
faultDesc[FaultID.SendableComputedPropName] = 'Sendable computed property name';
faultDesc[FaultID.SendableAsExpr] = 'Sendable as expr';
faultDesc[FaultID.SharedNoSideEffectImport] = 'Shared no side effect import';
faultDesc[FaultID.SharedModuleExports] = 'Shared module exports';
faultDesc[FaultID.SharedModuleNoWildcardExport] = 'Share module no wildcard export';
faultDesc[FaultID.NoTsImportEts] = 'No ts Import Ets';
faultDesc[FaultID.SendableTypeInheritance] = 'Sendable type inheritance';
faultDesc[FaultID.SendableTypeExported] = 'Sendable type exported';
faultDesc[FaultID.NoTsReExportEts] = 'No ts re-export ets';
faultDesc[FaultID.NoSIdeEffectImportEtsToTs] = 'No side effect import ets to ts';
faultDesc[FaultID.NoNameSpaceImportEtsToTs] = 'No namespace import ets to ts';
faultDesc[FaultID.SendableExplicitFieldType] = 'Field in sendable class must have type annotation';
faultDesc[FaultID.SendableFunctionImportedVariables] = 'Sendable function imported variables';
faultDesc[FaultID.SendableFunctionDecorator] = 'Sendable function decorator';
faultDesc[FaultID.SendableTypeAliasDecorator] = 'Sendable typeAlias decorator';
faultDesc[FaultID.SendableTypeAliasDeclaration] = 'Sendable typeAlias declaration';
faultDesc[FaultID.SendableFunctionAssignment] = 'Sendable function assignment';
faultDesc[FaultID.SendableFunctionOverloadDecorator] = 'Sendable function overload decorator';
faultDesc[FaultID.SendableFunctionProperty] = 'Sendable function property';
faultDesc[FaultID.SendableFunctionAsExpr] = 'Sendable function as expr';
faultDesc[FaultID.SendableDecoratorLimited] = 'Sendable decorator limited';
faultDesc[FaultID.SendableClosureExport] = 'Sendable closure export';
faultDesc[FaultID.SharedModuleExportsWarning] = 'Shared module exports Warning';
faultDesc[FaultID.SendableBetaCompatible] = 'Sendable beta compatible';
faultDesc[FaultID.ObjectLiteralProperty] = 'Object literal property';
faultDesc[FaultID.OptionalMethod] = 'Optional method';
faultDesc[FaultID.ImportType] = 'Import type syntax';
faultDesc[FaultID.DynamicCtorCall] = 'Dynamic constructor call';
