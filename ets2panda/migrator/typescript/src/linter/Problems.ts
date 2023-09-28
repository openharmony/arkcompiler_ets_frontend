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
import { cookBookMsg } from "./CookBookMsg";

export enum NodeType {
    AnyType,
    SymbolType,
    UnionType,
    TupleType,
    ObjectLiteralNoContextType,
    ArrayLiteralNoContextType,
    ComputedPropertyName,
    LiteralAsPropertyName,
    TypeOfExpression,
    TupleLiteral,
    UnionLiteral,
    RegexLiteral,
    IsOperator,
    DestructuringParameter,
    YieldExpression,
    InterfaceOrEnumMerging,
    InterfaceExtendsClass,
    IndexMember,
    WithStatement,
    ThrowStatement,
    IndexedAccessType,
    UndefinedType,
    UnknownType,
    ForInStatement,
    InOperator,
    SpreadOperator,
    KeyOfOperator,
    ImportFromPath,
    FunctionExpression,

    TypeParameterWithDefaultValue,
    IntersectionType,
    ObjectTypeLiteral,
    LogicalWithNonBoolean,
    AddWithWrongType,
    BitOpWithWrongType,
    CommaOperator,
    TopLevelStmt,

    IfWithNonBoolean,
    DoWithNonBoolean,
    WhileWithNonBoolean,
    FuncWithoutReturnType,
    ArrowFunctionWithOmittedTypes,
    LambdaWithTypeParameters,
    ClassExpression,
    DestructuringAssignment,
    DestructuringDeclaration,

    ForOfNonArray,
    VarDeclaration,
    CatchWithUnsupportedType,

    DeleteOperator,
    DeclWithDuplicateName,
    FuncOptionalParams,

    UnaryArithmNotNumber,
    LogNotWithNotBool,
    ConstructorType,
    CallSignature,
    TemplateLiteral,
    TypeAssertion,
    FunctionOverload,
    ConstructorOverload,

    PrivateIdentifier,
    LocalFunction,
    SwitchSelectorInvalidType,
    CaseExpressionNonConst,
    ConditionalType,
    MappedType,
    NamespaceAsObject,
    NonDeclarationInNamespace,
    GeneratorFunction,
    FunctionContainsThis,
    PropertyAccessByIndex,
    JsxElement,
    EnumMemberWithInitializer,

    ImplementsClass,
    MultipleStaticBlocks,
    //Decorators, // It's not a problem and counted temporary just to have statistic of decorators use.
    ThisType,
    InferType,
    SpreadAssignment,
    IntefaceExtendDifProps,
    DynamicTypeCheck,

    TypeOnlyImport,
    TypeOnlyExport,
    DefaultImport,
    DefaultExport,
    ExportRenaming,
    ExportListDeclaration,
    ReExporting,
    ExportAssignment,
    ImportAssignment,

    ObjectRuntimeCheck,
    GenericCallNoTypeArgs,

    BigIntType,
    BigIntLiteral,
    StringLiteralType,
    InterfaceOptionalProp,
    ParameterProperties,
    InstanceofUnsupported,
    GenericArrayType,
    ShorthandAmbientModuleDecl,
    WildcardsInModuleName,
    UMDModuleDefinition,
    JSExtensionInModuleIdent,
    NewTarget,
    DynamicImport,
    DefiniteAssignment,
    IifeAsNamespace,
    Prototype,
    GlobalThis,
    UtilityType,
    PropertyDeclOnFunction,
    FunctionApplyBindCall,
    ReadonlyArr,
    ConstAssertion,
    ImportAssertion,

    LAST_NODE_TYPE // this should always be last enum`
}

export class TsProblemInfo {
    tag?: string;
    suggestion?: string;
    printInRelaxMode?: boolean = true;
    cookBookRef: string;
 }

export var problemList: TsProblemInfo[] = [];

problemList[NodeType.AnyType] = {
    cookBookRef: "8"
}

problemList[NodeType.SymbolType] = {
    cookBookRef: "2"
}

problemList[NodeType.UnionType] = {
    cookBookRef: "18"
}

problemList[NodeType.TupleType] = {
    cookBookRef: "13"
}

problemList[NodeType.ObjectLiteralNoContextType] = {
    printInRelaxMode: false,
    cookBookRef: "38"
}

problemList[NodeType.ArrayLiteralNoContextType] = {
    printInRelaxMode: false,
    cookBookRef: "42"
}

problemList[NodeType.ComputedPropertyName] = {
    cookBookRef: "1"
}

problemList[NodeType.LiteralAsPropertyName] = {
    cookBookRef: "1"
}

problemList[NodeType.TypeOfExpression] = {
    cookBookRef: "60"
}

problemList[NodeType.TupleLiteral] = {
    cookBookRef: "13"
}

problemList[NodeType.UnionLiteral] = {
    cookBookRef: "18"
}

problemList[NodeType.RegexLiteral] = {
    cookBookRef: "37"
}

problemList[NodeType.IsOperator] = {
    cookBookRef: "96"
}

problemList[NodeType.DestructuringParameter] = {
    cookBookRef: "91"
}

problemList[NodeType.YieldExpression] = {
    cookBookRef: "94"
}

problemList[NodeType.InterfaceOrEnumMerging] = {
    cookBookRef: "103"
}

problemList[NodeType.InterfaceExtendsClass] = {
    cookBookRef: "104"
}

problemList[NodeType.IndexMember] = {
    cookBookRef: "17"
}

problemList[NodeType.WithStatement] = {
    cookBookRef: "84"
}

problemList[NodeType.ThrowStatement] = {
    printInRelaxMode: false,
    cookBookRef: "87"
}

problemList[NodeType.IndexedAccessType] = {
    cookBookRef: "28"
}

problemList[NodeType.UndefinedType] = {
    cookBookRef: "8"
}

problemList[NodeType.UnknownType] = {
    cookBookRef: "8"
}

problemList[NodeType.ForInStatement] = {
    cookBookRef: "80"
}

problemList[NodeType.InOperator] = {
    cookBookRef: "66"
}

problemList[NodeType.SpreadOperator] = {
    cookBookRef: "98"
}

problemList[NodeType.KeyOfOperator] = {
    cookBookRef: "97"
}

problemList[NodeType.ImportFromPath] = {
    cookBookRef: "119"
}

problemList[NodeType.FunctionExpression] = {
    printInRelaxMode: false,
    cookBookRef: "46"
}

problemList[NodeType.TypeParameterWithDefaultValue] = {
    printInRelaxMode: false,
    cookBookRef: "20"
}

problemList[NodeType.IntersectionType] = {
    cookBookRef: "19"
}

problemList[NodeType.ObjectTypeLiteral] = {
    cookBookRef: "40"
}

problemList[NodeType.LogicalWithNonBoolean] = {
    cookBookRef: "67"
}

problemList[NodeType.AddWithWrongType] = {
    cookBookRef: "63"
}

problemList[NodeType.BitOpWithWrongType] = {
    cookBookRef: "61"
}

problemList[NodeType.CommaOperator] = {
    cookBookRef: "71"
}

problemList[NodeType.TopLevelStmt] = {
    cookBookRef: "117"
}

problemList[NodeType.IfWithNonBoolean] = {
    printInRelaxMode: false,
    cookBookRef: "78"
}

problemList[NodeType.DoWithNonBoolean] = {
    printInRelaxMode: false,
    cookBookRef: "78"
}

problemList[NodeType.WhileWithNonBoolean] = {
    printInRelaxMode: false,
    cookBookRef: "78"
}

problemList[NodeType.FuncWithoutReturnType] = {
    printInRelaxMode: false,
    cookBookRef: "90"
}

problemList[NodeType.ArrowFunctionWithOmittedTypes] = {
    printInRelaxMode: false,
    cookBookRef: "45"
}

problemList[NodeType.LambdaWithTypeParameters] = {
    cookBookRef: "49"
}

problemList[NodeType.ClassExpression] = {
    printInRelaxMode: false,
    cookBookRef: "50"
}

problemList[NodeType.DestructuringAssignment] = {
    printInRelaxMode: false,
    cookBookRef: "69"
}

problemList[NodeType.DestructuringDeclaration] = {
    printInRelaxMode: false,
    cookBookRef: "74"
}

problemList[NodeType.ForOfNonArray] = {
    printInRelaxMode: false,
    cookBookRef: "82"
}

problemList[NodeType.VarDeclaration] = {
    printInRelaxMode: false,
    cookBookRef: "5"
}

problemList[NodeType.CatchWithUnsupportedType] = {
    printInRelaxMode: false,
    cookBookRef: "79"
}

problemList[NodeType.DeleteOperator] = {
    cookBookRef: "59"
}

problemList[NodeType.DeclWithDuplicateName] = {
    cookBookRef: "4"
}

problemList[NodeType.FuncOptionalParams] = {
    cookBookRef: "24"
}

problemList[NodeType.UnaryArithmNotNumber] = {
    cookBookRef: "55"
}

problemList[NodeType.LogNotWithNotBool] = {
    cookBookRef: "57"
}

problemList[NodeType.ConstructorType] = {
    cookBookRef: "15"
}

problemList[NodeType.CallSignature] = {
    cookBookRef: "14"
}

problemList[NodeType.TemplateLiteral] = {
    printInRelaxMode: false,
    cookBookRef: "44"
}

problemList[NodeType.TypeAssertion] = {
    cookBookRef: "53"
}

problemList[NodeType.FunctionOverload] = {
    cookBookRef: "88"
}


problemList[NodeType.ConstructorOverload] = {
    cookBookRef: "108"
}

problemList[NodeType.PrivateIdentifier] = {
    printInRelaxMode: false,
    cookBookRef: "3"
}

problemList[NodeType.LocalFunction] = {
    printInRelaxMode: false,
    cookBookRef: "92"
}

problemList[NodeType.SwitchSelectorInvalidType] = {
    cookBookRef: "86"
}

problemList[NodeType.CaseExpressionNonConst] = {
    cookBookRef: "85"
}

problemList[NodeType.ConditionalType] = {
    cookBookRef: "22"
}

problemList[NodeType.MappedType] = {
    cookBookRef: "83"
}

problemList[NodeType.NamespaceAsObject] = {
    cookBookRef: "114"
}

problemList[NodeType.NonDeclarationInNamespace] = {
    cookBookRef: "116"
}

problemList[NodeType.GeneratorFunction] = {
    cookBookRef: "94"
}

problemList[NodeType.FunctionContainsThis] = {
    cookBookRef: "93"
}

problemList[NodeType.PropertyAccessByIndex] = {
    cookBookRef: "29"
}

problemList[NodeType.JsxElement] = {
    cookBookRef: "54"
}

problemList[NodeType.EnumMemberWithInitializer] = {
    cookBookRef: "111"
}

problemList[NodeType.ImplementsClass] = {
    cookBookRef: "51"
}

problemList[NodeType.MultipleStaticBlocks] = {
    cookBookRef: "16"
}

problemList[NodeType.ThisType] = {
    cookBookRef: "21"
}

problemList[NodeType.InferType] = {
    cookBookRef: "76"
}

problemList[NodeType.SpreadAssignment] = {
    cookBookRef: "100"
}

problemList[NodeType.IntefaceExtendDifProps] = {
    cookBookRef: "102"
}

problemList[NodeType.DynamicTypeCheck] = {
    cookBookRef: "30"
}

problemList[NodeType.TypeOnlyImport] = {
    printInRelaxMode: false,
    cookBookRef: "118"
}

problemList[NodeType.TypeOnlyExport] = {
    printInRelaxMode: false,
    cookBookRef: "127"
}

problemList[NodeType.DefaultImport] = {
    printInRelaxMode: false,
    cookBookRef: "120"
}

problemList[NodeType.DefaultExport] = {
    printInRelaxMode: false,
    cookBookRef: "122"
}

problemList[NodeType.ExportRenaming] = {
    printInRelaxMode: false,
    cookBookRef: "123"
}

problemList[NodeType.ExportListDeclaration] = {
    printInRelaxMode: false,
    cookBookRef: "124"
}

problemList[NodeType.ReExporting] = {
    cookBookRef: "125"
}

problemList[NodeType.ExportAssignment] = {
    cookBookRef: "126"
}

problemList[NodeType.ImportAssignment] = {
    cookBookRef: "121"
}

problemList[NodeType.ObjectRuntimeCheck] = {
    cookBookRef: "105"
}

problemList[NodeType.GenericCallNoTypeArgs] = {
    printInRelaxMode: false,
    cookBookRef: "34"
}

problemList[NodeType.BigIntType] = {
    cookBookRef: "10"
}

problemList[NodeType.BigIntLiteral] = {
    cookBookRef: "10"
}

problemList[NodeType.StringLiteralType] = {
    cookBookRef: "11"
}

problemList[NodeType.InterfaceOptionalProp] = {
    cookBookRef: "33"
}

problemList[NodeType.ParameterProperties] = {
    printInRelaxMode: false,
    cookBookRef: "25"
}

problemList[NodeType.GenericArrayType] = {
    printInRelaxMode: false,
    cookBookRef: "12"
}

problemList[NodeType.InstanceofUnsupported] = {
    cookBookRef: "65"
}

problemList[NodeType.ShorthandAmbientModuleDecl] = {
    cookBookRef: "128"
}

problemList[NodeType.WildcardsInModuleName] = {
    cookBookRef: "129"
}

problemList[NodeType.UMDModuleDefinition] = {
    cookBookRef: "130"
}

problemList[NodeType.JSExtensionInModuleIdent] = {
    cookBookRef: "131"
}

problemList[NodeType.NewTarget] = {
    cookBookRef: "132"
};

problemList[NodeType.DynamicImport] = {
    cookBookRef: "133"
}

problemList[NodeType.DefiniteAssignment] = {
    cookBookRef: "134"
};

problemList[NodeType.IifeAsNamespace] = {
    cookBookRef: "135"
};

problemList[NodeType.Prototype] = {
    cookBookRef: "136"
}

problemList[NodeType.GlobalThis] = {
    cookBookRef: "137"
}

problemList[NodeType.UtilityType] = {
    cookBookRef: "138"
}

problemList[NodeType.PropertyDeclOnFunction] = {
    cookBookRef: "139"
}

problemList[NodeType.FunctionApplyBindCall] = {
    cookBookRef: "140"
}

problemList[NodeType.ReadonlyArr] = {
    cookBookRef: "141"
}

problemList[NodeType.ConstAssertion] = {
    cookBookRef: "142"
}

problemList[NodeType.ImportAssertion] = {
    cookBookRef: "143"
}
