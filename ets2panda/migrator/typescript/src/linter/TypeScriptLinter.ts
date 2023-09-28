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
import * as Utils from "./Utils";
import { NodeType, TsProblemInfo, problemList } from "./Problems";
import { cookBookMsg, cookBookTag } from "./CookBookMsg";

class BadNodeInfo {
  line: number;
  column: number;
  start: number;
  end: number;
  type: string;
  problem: string;
  suggest: string;
  rule: string;
}

export class TypeScriptLinter {
  static IDE_mode: boolean = false;
  static STRICT_mode: boolean = false;
  static TSC_Errors: boolean = false;
  static nodeCntr = 0;
  static nodeCounters: number[] = [];
  static lineCounters: number[] = [];
  static printInRelaxModeFlags: boolean[] = []; // Set flag to 'false' only for features that should NOT be printed in Relax mode!
  static nodeDescription: string[] = [];
  static lineNumbersString: string = "";
  static lineNumbersStringPosCntr: number = 0;
  static specificNodeLineNumbers: string = "";
  static specificNodeLineNumbersPosCntr: number = 0;
  static commonLineCounter = 0;
  // static unionTNull = 0; // It's now a part of STS language --> not a problem any more.
  // static unionTAny = 0;
  // static unionTUndefined = 0;
  static objLiteralNotParameter = 0;

  // The SyntaxKind enum defines additional elements at the end of the enum
  // that serve as markers (FirstX/LastX). Those elements are initialized
  // with indices of the previously defined elements. As result, the enum
  // may return incorrect name for a certain kind index (e.g. 'FirstStatement'
  // instead of 'VariableStatement').
  // The following code creates a map with correct syntax kind names.
  // It can be used when need to print name of syntax kind of certain
  // AST node in diagnostic messages.
  private static tsSyntaxKindNames: string[];
  static {
    let newArray: string[] = [];
    let keys = Object.keys(ts.SyntaxKind);
    let values = Object.values(ts.SyntaxKind);

    for (let i = 0; i < values.length; i++) {
      let val = values[i];
      let kindNum = typeof val === "string" ? parseInt(val) : val;
      if (kindNum && !newArray[kindNum]) {
        newArray[kindNum] = keys[i];
      }
    }

    TypeScriptLinter.tsSyntaxKindNames = newArray;
  }

  static {
    for (let i = 0; i < NodeType.LAST_NODE_TYPE; i++) {
      TypeScriptLinter.nodeCounters[i] = 0;
      TypeScriptLinter.lineCounters[i] = 0;
      TypeScriptLinter.printInRelaxModeFlags[i] = true;
    }
  }

  static {
    // Set the feature descriptions (for the output).
    TypeScriptLinter.nodeDescription[NodeType.AnyType] =
      "'Any' type nodes                            ";
    TypeScriptLinter.nodeDescription[NodeType.SymbolType] =
      "'Symbol' type nodes                         ";
    TypeScriptLinter.nodeDescription[NodeType.UnionType] =
      "Union type nodes                            ";
    TypeScriptLinter.nodeDescription[NodeType.TupleType] =
      "Tuple type nodes                            ";
    TypeScriptLinter.nodeDescription[NodeType.ObjectLiteralNoContextType] =
      "Object literals with no context Class type  ";
    TypeScriptLinter.nodeDescription[NodeType.ArrayLiteralNoContextType] =
      "Array literals with no context Array type   ";
    TypeScriptLinter.nodeDescription[NodeType.ComputedPropertyName] =
      "Computed property nodes                     ";
    TypeScriptLinter.nodeDescription[NodeType.LiteralAsPropertyName] =
      "String or integer literal as property name  ";
    TypeScriptLinter.nodeDescription[NodeType.TypeOfExpression] =
      "'typeof' operations                         ";
    TypeScriptLinter.nodeDescription[NodeType.TupleLiteral] =
      "tuple literals                              ";
    TypeScriptLinter.nodeDescription[NodeType.UnionLiteral] =
      "union type literals                         ";
    TypeScriptLinter.nodeDescription[NodeType.RegexLiteral] =
      "regex literals                              ";
    TypeScriptLinter.nodeDescription[NodeType.IsOperator] =
      "'is' operations                             ";
    TypeScriptLinter.nodeDescription[NodeType.DestructuringParameter] =
      "destructuring parameters                    ";
    TypeScriptLinter.nodeDescription[NodeType.YieldExpression] =
      "'yield' operations                          ";
    TypeScriptLinter.nodeDescription[NodeType.InterfaceOrEnumMerging] =
      "merging interfaces or enums                 ";
    TypeScriptLinter.nodeDescription[NodeType.InterfaceExtendsClass] =
      "interfaces inherited from classes           ";
    TypeScriptLinter.nodeDescription[NodeType.IndexMember] =
      "index members                               ";
    TypeScriptLinter.nodeDescription[NodeType.WithStatement] =
      "'with' statements                           ";
    TypeScriptLinter.nodeDescription[NodeType.ThrowStatement] =
      "'throw' statements                          ";
    TypeScriptLinter.nodeDescription[NodeType.IndexedAccessType] =
      "Indexed access type nodes                   ";
    TypeScriptLinter.nodeDescription[NodeType.UndefinedType] =
      "'undef' type nodes                          ";
    TypeScriptLinter.nodeDescription[NodeType.UnknownType] =
      "'unknown' type nodes                        ";
    TypeScriptLinter.nodeDescription[NodeType.ForInStatement] =
      "'For-In' statements                         ";
    TypeScriptLinter.nodeDescription[NodeType.InOperator] =
      "'in' operators                              ";
    TypeScriptLinter.nodeDescription[NodeType.SpreadOperator] =
      "'spread' operations                         ";
    TypeScriptLinter.nodeDescription[NodeType.KeyOfOperator] =
      "'keyof' operations                          ";
    TypeScriptLinter.nodeDescription[NodeType.ImportFromPath] =
      "imports from path nodes                     ";

    TypeScriptLinter.nodeDescription[NodeType.FunctionExpression] =
      "function expression nodes                   ";
    TypeScriptLinter.nodeDescription[NodeType.TypeParameterWithDefaultValue] =
      "type parameters with default value          ";
    TypeScriptLinter.nodeDescription[NodeType.IntersectionType] =
      "intersection types and type literals        ";
    TypeScriptLinter.nodeDescription[NodeType.ObjectTypeLiteral] =
      "Object type literals                        ";
    TypeScriptLinter.nodeDescription[NodeType.LogicalWithNonBoolean] =
      "'&&' or '||' with non-'boolean' operand     ";
    TypeScriptLinter.nodeDescription[NodeType.AddWithWrongType] =
      "binary '+' with wrong operand               ";
    TypeScriptLinter.nodeDescription[NodeType.BitOpWithWrongType] =
      "bit operation with wrong operand            ";
    TypeScriptLinter.nodeDescription[NodeType.CommaOperator] =
      "comma operator                              ";
    TypeScriptLinter.nodeDescription[NodeType.TopLevelStmt] =
      "statement at top level                      ";

    TypeScriptLinter.nodeDescription[NodeType.IfWithNonBoolean] =
      "'If' with non-'boolean' condition           ";
    TypeScriptLinter.nodeDescription[NodeType.DoWithNonBoolean] =
      "'Do' with non-'boolean' condition           ";
    TypeScriptLinter.nodeDescription[NodeType.WhileWithNonBoolean] =
      "'While' with non-'boolean' condition        ";
    TypeScriptLinter.nodeDescription[NodeType.FuncWithoutReturnType] =
      "Functions without return type               ";
    TypeScriptLinter.nodeDescription[NodeType.ArrowFunctionWithOmittedTypes] =
      "Arrow functions with omitted types          ";
    TypeScriptLinter.nodeDescription[NodeType.LambdaWithTypeParameters] =
      "Lambda function with type parameters        ";
    TypeScriptLinter.nodeDescription[NodeType.ClassExpression] =
      "Class expression nodes                      ";
    TypeScriptLinter.nodeDescription[NodeType.DestructuringAssignment] =
      "Destructuring assignments                   ";
    TypeScriptLinter.nodeDescription[NodeType.DestructuringDeclaration] =
      "Destructuring variable declarations         ";

    TypeScriptLinter.nodeDescription[NodeType.ForOfNonArray] =
      "'For-of' statemens for non-array object     ";
    TypeScriptLinter.nodeDescription[NodeType.VarDeclaration] =
      "'var' declarations                          ";
    TypeScriptLinter.nodeDescription[NodeType.CatchWithUnsupportedType] =
      "'catch' with unsuported type                ";

    TypeScriptLinter.nodeDescription[NodeType.DeleteOperator] =
      "'delete' operators                          ";
    TypeScriptLinter.nodeDescription[NodeType.DeclWithDuplicateName] =
      "Declarations with duplicate name            ";
    TypeScriptLinter.nodeDescription[NodeType.FuncOptionalParams] =
      "Optional parameters in function             ";

    TypeScriptLinter.nodeDescription[NodeType.UnaryArithmNotNumber] =
      "Unary arithmetics with not-numeric values   ";
    TypeScriptLinter.nodeDescription[NodeType.LogNotWithNotBool] =
      "Logical not with not-boolean values         ";
    TypeScriptLinter.nodeDescription[NodeType.ConstructorType] =
      "Constructor type nodes                      ";
    TypeScriptLinter.nodeDescription[NodeType.CallSignature] =
      "Call signatures                             ";
    TypeScriptLinter.nodeDescription[NodeType.TemplateLiteral] =
      "Template literals                           ";
    TypeScriptLinter.nodeDescription[NodeType.TypeAssertion] =
      "Type Assertion expressions                  ";
    TypeScriptLinter.nodeDescription[NodeType.FunctionOverload] =
      "Function overload in TS style               ";
    TypeScriptLinter.nodeDescription[NodeType.ConstructorOverload] =
      "Constructor overload in TS style            ";
    TypeScriptLinter.nodeDescription[NodeType.PrivateIdentifier] =
      "Private identifiers (with '#' prefix)       ";
    TypeScriptLinter.nodeDescription[NodeType.LocalFunction] =
      "Local function declarations                 ";
    TypeScriptLinter.nodeDescription[NodeType.SwitchSelectorInvalidType] =
      "Switch selectors with invalid type          ";
    TypeScriptLinter.nodeDescription[NodeType.CaseExpressionNonConst] =
      "Non-constant Case expressions               ";
    TypeScriptLinter.nodeDescription[NodeType.ConditionalType] =
      "Conditional type                            ";
    TypeScriptLinter.nodeDescription[NodeType.MappedType] =
      "Mapped types                                ";
    TypeScriptLinter.nodeDescription[NodeType.NamespaceAsObject] =
      "Namespaces used as objects                  ";
    TypeScriptLinter.nodeDescription[NodeType.NonDeclarationInNamespace] =
      "Non-declaration statements in namespaces    ";
    TypeScriptLinter.nodeDescription[NodeType.GeneratorFunction] =
      "Generator functions                         ";
    TypeScriptLinter.nodeDescription[NodeType.FunctionContainsThis] =
      "Functions containing 'this'                 ";
    TypeScriptLinter.nodeDescription[NodeType.PropertyAccessByIndex] =
      "property access by index                    ";
    TypeScriptLinter.nodeDescription[NodeType.JsxElement] =
      "JSX Elements                                ";
    TypeScriptLinter.nodeDescription[NodeType.EnumMemberWithInitializer] =
      "Enum members with initializer               ";

    TypeScriptLinter.nodeDescription[NodeType.ImplementsClass] =
      "'implements' a class                        ";
    TypeScriptLinter.nodeDescription[NodeType.MultipleStaticBlocks] =
      "Multiple static blocks                      ";
    //TypeScriptLinter.nodeDescription[NodeType.Decorators] =                   "Decorators                                  "; // It's not a problem and counted temporary just to have statistic of decorators use.
    TypeScriptLinter.nodeDescription[NodeType.ThisType] =
      "'this' type                                 ";
    TypeScriptLinter.nodeDescription[NodeType.InferType] =
      "Infer type                                  ";
    TypeScriptLinter.nodeDescription[NodeType.SpreadAssignment] =
      "Spread assignment                           ";
    TypeScriptLinter.nodeDescription[NodeType.IntefaceExtendDifProps] =
      "Extends same properties with diff. types    ";
    TypeScriptLinter.nodeDescription[NodeType.DynamicTypeCheck] =
      "Dynamic type check                          ";

    TypeScriptLinter.nodeDescription[NodeType.TypeOnlyImport] =
      "Type-only imports                           ";
    TypeScriptLinter.nodeDescription[NodeType.TypeOnlyExport] =
      "Type-only exports                           ";
    TypeScriptLinter.nodeDescription[NodeType.DefaultImport] =
      "Default import declarations                 ";
    TypeScriptLinter.nodeDescription[NodeType.DefaultExport] =
      "Default export declarations                 ";
    TypeScriptLinter.nodeDescription[NodeType.ExportRenaming] =
      "Renaming in export declarations             ";
    TypeScriptLinter.nodeDescription[NodeType.ExportListDeclaration] =
      "Export list declarations                    ";
    TypeScriptLinter.nodeDescription[NodeType.ReExporting] =
      "Re-exporting declarations                   ";
    TypeScriptLinter.nodeDescription[NodeType.ExportAssignment] =
      "Export assignments (export = ..)            ";
    TypeScriptLinter.nodeDescription[NodeType.ImportAssignment] =
      "Import assignments (import = ..)            ";

    TypeScriptLinter.nodeDescription[NodeType.ObjectRuntimeCheck] =
      "Object runtime checks                       ";
    TypeScriptLinter.nodeDescription[NodeType.GenericCallNoTypeArgs] =
      "Generic calls without specifying type args  ";

    TypeScriptLinter.nodeDescription[NodeType.BigIntType] =
      "'bigint' type                               ";
    TypeScriptLinter.nodeDescription[NodeType.BigIntLiteral] =
      "bigint literal                              ";
    TypeScriptLinter.nodeDescription[NodeType.StringLiteralType] =
      "string literal type                         ";
    TypeScriptLinter.nodeDescription[NodeType.InterfaceOptionalProp] =
      "Interface optional property                 ";
    TypeScriptLinter.nodeDescription[NodeType.ParameterProperties] =
      "Parameter properties in constructor         ";
    TypeScriptLinter.nodeDescription[NodeType.InstanceofUnsupported] =
      "Left-hand side of 'instanceof' is wrong     ";
    TypeScriptLinter.nodeDescription[NodeType.GenericArrayType] =
      "'Array<T>' type                             ";

    TypeScriptLinter.nodeDescription[NodeType.ShorthandAmbientModuleDecl] =
      "Shorthand ambient module declaration        ";
    TypeScriptLinter.nodeDescription[NodeType.WildcardsInModuleName] =
      "Wildcards in module name                    ";
    TypeScriptLinter.nodeDescription[NodeType.UMDModuleDefinition] =
      "UMD module definition                       ";
    TypeScriptLinter.nodeDescription[NodeType.JSExtensionInModuleIdent] =
      ".js extension in module identifier          ";
    TypeScriptLinter.nodeDescription[NodeType.NewTarget] =
      "'new.target' meta-property                  ";
    TypeScriptLinter.nodeDescription[NodeType.DynamicImport] =
      "Dynamic import expression                   ";
    TypeScriptLinter.nodeDescription[NodeType.DefiniteAssignment] =
      "Definite assignment assertion               ";
    TypeScriptLinter.nodeDescription[NodeType.IifeAsNamespace] =
      "IIFEs as namespace declarations             ";
    TypeScriptLinter.nodeDescription[NodeType.Prototype] =
      "Prototype assignment                        ";
    TypeScriptLinter.nodeDescription[NodeType.GlobalThis] =
      "Use of globalThis                           ";
    TypeScriptLinter.nodeDescription[NodeType.UtilityType] =
      "Standard Utility types                      ";
    TypeScriptLinter.nodeDescription[NodeType.PropertyDeclOnFunction] =
      "Property declaration on function            ";
    TypeScriptLinter.nodeDescription[NodeType.FunctionApplyBindCall] =
      "Invoking methods of function objects        ";
    TypeScriptLinter.nodeDescription[NodeType.ReadonlyArr] =
      "'readonly' array or tuple                   ";
    TypeScriptLinter.nodeDescription[NodeType.ConstAssertion] =
      "'as const' assertion                        ";
    TypeScriptLinter.nodeDescription[NodeType.ImportAssertion] =
      "Import assertion                            ";
  }

  static {
    // Specify features that should NOT be counted and printed in Relax mode.

    TypeScriptLinter.printInRelaxModeFlags[NodeType.FunctionExpression] = false;
    TypeScriptLinter.printInRelaxModeFlags[
      NodeType.TypeParameterWithDefaultValue
    ] = false;

    TypeScriptLinter.printInRelaxModeFlags[NodeType.IfWithNonBoolean] = false;
    TypeScriptLinter.printInRelaxModeFlags[NodeType.DoWithNonBoolean] = false;
    TypeScriptLinter.printInRelaxModeFlags[NodeType.WhileWithNonBoolean] =
      false;
    TypeScriptLinter.printInRelaxModeFlags[NodeType.FuncWithoutReturnType] =
      false;

    TypeScriptLinter.printInRelaxModeFlags[
      NodeType.ArrowFunctionWithOmittedTypes
    ] = false;
    TypeScriptLinter.printInRelaxModeFlags[NodeType.ClassExpression] = false;
    TypeScriptLinter.printInRelaxModeFlags[NodeType.DestructuringAssignment] =
      false;
    TypeScriptLinter.printInRelaxModeFlags[NodeType.DestructuringDeclaration] =
      false;

    TypeScriptLinter.printInRelaxModeFlags[NodeType.ForOfNonArray] = false;
    TypeScriptLinter.printInRelaxModeFlags[NodeType.VarDeclaration] = false;
    TypeScriptLinter.printInRelaxModeFlags[NodeType.CatchWithUnsupportedType] =
      false;
    TypeScriptLinter.printInRelaxModeFlags[NodeType.PrivateIdentifier] = false;
    TypeScriptLinter.printInRelaxModeFlags[NodeType.LocalFunction] = false;
    TypeScriptLinter.printInRelaxModeFlags[NodeType.TemplateLiteral] = false;
    TypeScriptLinter.printInRelaxModeFlags[NodeType.ThrowStatement] = false;

    TypeScriptLinter.printInRelaxModeFlags[NodeType.TypeOnlyImport] = false;
    TypeScriptLinter.printInRelaxModeFlags[NodeType.TypeOnlyExport] = false;
    TypeScriptLinter.printInRelaxModeFlags[NodeType.DefaultImport] = false;
    TypeScriptLinter.printInRelaxModeFlags[NodeType.DefaultExport] = false;
    TypeScriptLinter.printInRelaxModeFlags[NodeType.ExportRenaming] = false;
    TypeScriptLinter.printInRelaxModeFlags[NodeType.ExportListDeclaration] =
      false;

    TypeScriptLinter.printInRelaxModeFlags[NodeType.GenericCallNoTypeArgs] =
      false;
    TypeScriptLinter.printInRelaxModeFlags[NodeType.ParameterProperties] =
      false;
  }

  static badNodeInfos: BadNodeInfo[] = [];

  static tsTypeChecker: ts.TypeChecker;

  currentLine: number;
  staticBlocks: Set<String>;
  decorators: Map<String, number>;

  standardUtilityTypes = [
    "Awaited",
    "Partial",
    "Required",
    "Readonly",
    "Record",
    "Pick",
    "Omit",
    "Exclude",
    "Extract",
    "NonNullable",
    "Parameters",
    "ConstructorParameters",
    "ReturnType",
    "InstanceType",
    "ThisParameterType",
    "OmitThisParameter",
    "ThisType",
    "Uppercase",
    "Lowercase",
    "Capitalize",
    "Uncapitalize",
  ];

  constructor(
    private tsSourceFile: ts.SourceFile,
    private tsProgram: ts.Program
  ) {
    TypeScriptLinter.tsTypeChecker = tsProgram.getTypeChecker();
    this.currentLine = 0;
    this.staticBlocks = new Set<String>();
    this.decorators = new Map<String, number>();
  }

  public incrementCounters(node: ts.Node, nodeType: number) {
    TypeScriptLinter.nodeCounters[nodeType]++;

    // TSC counts lines and columns from zero
    let { line, character } = this.tsSourceFile.getLineAndCharacterOfPosition(
      node.getStart()
    );
    ++line;
    ++character;

    if (
      TypeScriptLinter.STRICT_mode ||
      TypeScriptLinter.printInRelaxModeFlags[nodeType]
    ) {
      if (!TypeScriptLinter.IDE_mode) {
        console.log(
          `Warning: ${this.tsSourceFile.fileName}(${line},${character}): ${
            TypeScriptLinter.nodeDescription[nodeType]
              ? TypeScriptLinter.nodeDescription[nodeType].trim()
              : TypeScriptLinter.tsSyntaxKindNames[node.kind]
          }`
        );
        if (problemList[nodeType] && problemList[nodeType].suggestion) {
          console.log(
            "\tSuggestion: " +
              problemList[nodeType].suggestion +
              " CookBook ref. #" +
              problemList[nodeType].cookBookRef
          );
        }
      } else {
        let cookBookMsgNum = problemList[nodeType]
          ? Number(problemList[nodeType].cookBookRef)
          : 0;
        let badNodeInfo: BadNodeInfo = {
          line: line,
          column: character,
          start: node.getStart(),
          end: node.getEnd(),
          type: TypeScriptLinter.tsSyntaxKindNames[node.kind],
          problem: NodeType[nodeType],
          //suggest: problemList[nodeType] ? problemList[nodeType].suggestion + "\n\t CookBook Ref. #" + problemList[nodeType].cookBookRef : ""
          suggest: cookBookMsgNum > 0 ? cookBookMsg[cookBookMsgNum] : "",
          rule:
            cookBookMsgNum > 0 && cookBookTag[cookBookMsgNum] !== ""
              ? cookBookTag[cookBookMsgNum]
              : TypeScriptLinter.nodeDescription[nodeType]
              ? TypeScriptLinter.nodeDescription[nodeType].trim()
              : TypeScriptLinter.tsSyntaxKindNames[node.kind],
        };

        TypeScriptLinter.badNodeInfos.push(badNodeInfo);
      }
    }

    TypeScriptLinter.lineCounters[nodeType]++;

    if (line != this.currentLine) {
      this.currentLine = line;
      if (
        TypeScriptLinter.STRICT_mode ||
        TypeScriptLinter.printInRelaxModeFlags[nodeType]
      ) {
        TypeScriptLinter.commonLineCounter++;
        TypeScriptLinter.lineNumbersString += String(line) + ", ";
        TypeScriptLinter.lineNumbersStringPosCntr++;
        if (TypeScriptLinter.lineNumbersStringPosCntr % 20 === 0)
          TypeScriptLinter.lineNumbersString += "\n\t\t ";
      }
    }

    if (node.kind === ts.SyntaxKind.UnionType) {
      TypeScriptLinter.specificNodeLineNumbers += String(line) + ", ";
      TypeScriptLinter.specificNodeLineNumbersPosCntr++;
      if (TypeScriptLinter.specificNodeLineNumbersPosCntr % 20 === 0)
        TypeScriptLinter.specificNodeLineNumbers += "\n\t\t ";
    }
  }

  public CountTSNodes(srcFile: ts.SourceFile) {
    let self = this;

    visitTSNode(srcFile);

    function visitTSNode(node: ts.Node) {
      if (node == null || node.kind == null) return;

      // check for top-level statements
      if (
        Utils.isStatementKindNode(node) &&
        node.kind != ts.SyntaxKind.VariableStatement
      ) {
        if (node.parent && node.parent.kind === ts.SyntaxKind.SourceFile)
          self.incrementCounters(node, NodeType.TopLevelStmt);
      }

      switch (node.kind) {
        // if( node.kind is TriviaSyntaxKind) break;
        //case ts.SyntaxKind.PunctuationSyntaxKind:
        //case ts.SyntaxKind.KeywordSyntaxKind:
        //case ts.SyntaxKind.ModifierSyntaxKind:
        //case ts.SyntaxKind.KeywordTypeSyntaxKind:
        //case ts.SyntaxKind.TypeNodeSyntaxKind:
        //case ts.SyntaxKind.TokenSyntaxKind:
        //case ts.SyntaxKind.JsxTokenSyntaxKind:
        //case ts.SyntaxKind.JsxTokenSyntaxKind:
        //   break;

        case ts.SyntaxKind.OpenBraceToken:
        case ts.SyntaxKind.CloseBraceToken:
        case ts.SyntaxKind.OpenParenToken:
        case ts.SyntaxKind.CloseParenToken:
        case ts.SyntaxKind.OpenBracketToken:
        case ts.SyntaxKind.CloseBracketToken:
        case ts.SyntaxKind.DotToken:
        case ts.SyntaxKind.DotDotDotToken:
        case ts.SyntaxKind.SemicolonToken:
        case ts.SyntaxKind.CommaToken:
        case ts.SyntaxKind.QuestionDotToken:
        case ts.SyntaxKind.LessThanToken:
        case ts.SyntaxKind.LessThanSlashToken:
        case ts.SyntaxKind.GreaterThanToken:
        case ts.SyntaxKind.LessThanEqualsToken:
        case ts.SyntaxKind.GreaterThanEqualsToken:
        case ts.SyntaxKind.EqualsEqualsToken:
        case ts.SyntaxKind.ExclamationEqualsToken:
        case ts.SyntaxKind.EqualsEqualsEqualsToken:
        case ts.SyntaxKind.ExclamationEqualsEqualsToken:
        case ts.SyntaxKind.EqualsGreaterThanToken:
        case ts.SyntaxKind.PlusToken:
        case ts.SyntaxKind.MinusToken:
        case ts.SyntaxKind.AsteriskToken:
        case ts.SyntaxKind.AsteriskAsteriskToken:
        case ts.SyntaxKind.SlashToken:
        case ts.SyntaxKind.PercentToken:
        case ts.SyntaxKind.PlusPlusToken:
        case ts.SyntaxKind.MinusMinusToken:
        case ts.SyntaxKind.LessThanLessThanToken:
        case ts.SyntaxKind.GreaterThanGreaterThanToken:
        case ts.SyntaxKind.GreaterThanGreaterThanGreaterThanToken:
        case ts.SyntaxKind.AmpersandToken:
        case ts.SyntaxKind.BarToken:
        case ts.SyntaxKind.CaretToken:
        case ts.SyntaxKind.ExclamationToken:
        case ts.SyntaxKind.TildeToken:
        case ts.SyntaxKind.AmpersandAmpersandToken:
        case ts.SyntaxKind.BarBarToken:
        case ts.SyntaxKind.QuestionQuestionToken:
        case ts.SyntaxKind.QuestionToken:
        case ts.SyntaxKind.ColonToken:
        case ts.SyntaxKind.AtToken:
        case ts.SyntaxKind.BacktickToken:
        case ts.SyntaxKind.HashToken:
        case ts.SyntaxKind.EqualsToken:
        case ts.SyntaxKind.PlusEqualsToken:
        case ts.SyntaxKind.MinusEqualsToken:
        case ts.SyntaxKind.AsteriskEqualsToken:
        case ts.SyntaxKind.AsteriskAsteriskEqualsToken:
        case ts.SyntaxKind.SlashEqualsToken:
        case ts.SyntaxKind.PercentEqualsToken:
        case ts.SyntaxKind.LessThanLessThanEqualsToken:
        case ts.SyntaxKind.GreaterThanGreaterThanEqualsToken:
        case ts.SyntaxKind.GreaterThanGreaterThanGreaterThanEqualsToken:
        case ts.SyntaxKind.AmpersandEqualsToken:
        case ts.SyntaxKind.BarEqualsToken:
        case ts.SyntaxKind.CaretEqualsToken:
        case ts.SyntaxKind.Unknown:
        case ts.SyntaxKind.EndOfFileToken:
        case ts.SyntaxKind.SingleLineCommentTrivia:
        case ts.SyntaxKind.MultiLineCommentTrivia:
        case ts.SyntaxKind.NewLineTrivia:
        case ts.SyntaxKind.WhitespaceTrivia:
        // We detect and preserve #! on the first line
        case ts.SyntaxKind.ShebangTrivia:
        // We detect and provide better error recovery when we encounter a git merge marker.  This
        // allows us to edit files with git-conflict markers in them in a much more pleasant manner.
        case ts.SyntaxKind.ConflictMarkerTrivia:
          // We don't want to increase counters for these tokens.
          return;

        /// Problem syntax kinds start here
        //
        case ts.SyntaxKind.AnyKeyword:
          self.incrementCounters(node, NodeType.AnyType);
          break;

        case ts.SyntaxKind.BigIntKeyword:
          self.incrementCounters(node, NodeType.BigIntType);
          break;

        case ts.SyntaxKind.BigIntLiteral:
          self.incrementCounters(node, NodeType.BigIntLiteral);
          break;

        case ts.SyntaxKind.SymbolKeyword:
          self.incrementCounters(node, NodeType.SymbolType);
          break;

        case ts.SyntaxKind.UnionType:
          // 'Type | null' now is a part of STS language. All other cases of union type should be counted as a problem.
          let tsUT = node as ts.UnionTypeNode;
          let uTypes = tsUT.types;

          if (
            uTypes.length !== 2 ||
            (!Utils.isNullType(uTypes[0]) && !Utils.isNullType(uTypes[1]))
          )
            self.incrementCounters(node, NodeType.UnionType);

          break;

        case ts.SyntaxKind.ThisType:
          self.incrementCounters(node, NodeType.ThisType);
          break;

        case ts.SyntaxKind.InferType:
          self.incrementCounters(node, NodeType.InferType);
          break;

        case ts.SyntaxKind.TupleType:
          self.incrementCounters(node, NodeType.TupleType);
          break;

        case ts.SyntaxKind.ObjectLiteralExpression:
          let tsObjectLiteralExpr = node as ts.ObjectLiteralExpression;

          // If object literal is a part of destructuring assignment, then
          // don't process it further.
          if (Utils.isDestructuringAssignmentLHS(tsObjectLiteralExpr)) break;

          let tsObjectLiteralContextType =
            TypeScriptLinter.tsTypeChecker.getContextualType(
              tsObjectLiteralExpr
            );
          if (
            !(
              tsObjectLiteralContextType && tsObjectLiteralContextType.isClass()
            )
          )
            self.incrementCounters(node, NodeType.ObjectLiteralNoContextType);

          if (node.parent.kind !== ts.SyntaxKind.CallExpression) {
            TypeScriptLinter.objLiteralNotParameter++;
          }

          break;

        case ts.SyntaxKind.ComputedPropertyName:
          self.incrementCounters(node, NodeType.ComputedPropertyName);
          break;

        case ts.SyntaxKind.TypeOfExpression:
          self.incrementCounters(node, NodeType.TypeOfExpression);
          break;

        case ts.SyntaxKind.DeleteExpression:
          self.incrementCounters(node, NodeType.DeleteOperator);

        case ts.SyntaxKind.ArrayLiteralExpression:
          // If array literal is a part of destructuring assignment, then
          // don't process it further.
          if (
            Utils.isDestructuringAssignmentLHS(
              node as ts.ArrayLiteralExpression
            )
          )
            break;

          let arrayLitNode = node as ts.ArrayLiteralExpression;
          //let literalType = TypeScriptLinter.tsTypeChecker.getTypeAtLocation(arrayLitNode);

          // check element types
          if (ts.isUnionTypeNode(arrayLitNode)) {
            self.incrementCounters(node, NodeType.TupleLiteral);
          }

          let noContextTypeForArrayLiteral = true;
          let tsArrayLiteralCtxType =
            TypeScriptLinter.tsTypeChecker.getContextualType(arrayLitNode);
          if (tsArrayLiteralCtxType) {
            let tsArrayLiteralCtxTypeNode =
              TypeScriptLinter.tsTypeChecker.typeToTypeNode(
                tsArrayLiteralCtxType,
                undefined,
                ts.NodeBuilderFlags.None
              );
            if (
              tsArrayLiteralCtxTypeNode &&
              Utils.isArrayNotTupleType(tsArrayLiteralCtxTypeNode)
            ) {
              noContextTypeForArrayLiteral = false;
            }
          }

          if (noContextTypeForArrayLiteral)
            self.incrementCounters(node, NodeType.ArrayLiteralNoContextType);

          break;

        case ts.SyntaxKind.RegularExpressionLiteral:
          self.incrementCounters(node, NodeType.RegexLiteral);
          break;

        case ts.SyntaxKind.TypePredicate:
          self.incrementCounters(node, NodeType.IsOperator);
          break;

        case ts.SyntaxKind.Parameter:
          let tsParam = node as ts.ParameterDeclaration;
          if (
            ts.isArrayBindingPattern(tsParam.name) ||
            ts.isObjectBindingPattern(tsParam.name)
          )
            self.incrementCounters(node, NodeType.DestructuringParameter);

          let tsParamMods = ts.getModifiers(tsParam);
          if (
            Utils.hasModifier(tsParamMods, ts.SyntaxKind.PublicKeyword) ||
            Utils.hasModifier(tsParamMods, ts.SyntaxKind.ProtectedKeyword) ||
            Utils.hasModifier(tsParamMods, ts.SyntaxKind.PrivateKeyword)
          )
            self.incrementCounters(node, NodeType.ParameterProperties);

          break;

        case ts.SyntaxKind.YieldExpression:
          self.incrementCounters(node, NodeType.YieldExpression);
          break;

        case ts.SyntaxKind.EnumDeclaration:
          let enumNode = node as ts.EnumDeclaration;
          const enumSymbol = TypeScriptLinter.tsTypeChecker.getSymbolAtLocation(
            enumNode.name
          );
          if (enumSymbol) {
            const enumDecls = enumSymbol.getDeclarations();
            if (enumDecls) {
              // Since type checker merges all declarations with the same name
              // into one symbol, we need to check that there's more than one
              // enum declaration related to that specific symbol.
              // See 'countDeclarationsWithDuplicateName' method for details.
              let enumDeclCount = 0;
              for (const decl of enumDecls) {
                if (decl.kind === ts.SyntaxKind.EnumDeclaration)
                  enumDeclCount++;
              }

              if (enumDeclCount > 1) {
                self.incrementCounters(node, NodeType.InterfaceOrEnumMerging);
              }
            }
          }

          self.countDeclarationsWithDuplicateName(
            TypeScriptLinter.tsTypeChecker.getSymbolAtLocation(enumNode.name),
            enumNode
          );

          break;

        case ts.SyntaxKind.InterfaceDeclaration:
          let interfaceNode = node as ts.InterfaceDeclaration;

          const iSymbol = TypeScriptLinter.tsTypeChecker.getSymbolAtLocation(
            interfaceNode.name
          );
          if (iSymbol) {
            const iDecls = iSymbol.getDeclarations();
            if (iDecls) {
              // Since type checker merges all declarations with the same name
              // into one symbol, we need to check that there's more than one
              // interface declaration related to that specific symbol.
              // See 'countDeclarationsWithDuplicateName' method for details.
              let iDeclCount = 0;
              for (const decl of iDecls) {
                if (decl.kind === ts.SyntaxKind.InterfaceDeclaration)
                  iDeclCount++;
              }

              if (iDeclCount > 1) {
                self.incrementCounters(node, NodeType.InterfaceOrEnumMerging);
              }
            }
          }

          if (interfaceNode.heritageClauses) {
            for (const hClause of interfaceNode.heritageClauses) {
              if (hClause.token === ts.SyntaxKind.ExtendsKeyword) {
                let prop2type = new Map<string, string>();

                for (const tsTypeExpr of hClause.types) {
                  let tsExprType =
                    TypeScriptLinter.tsTypeChecker.getTypeAtLocation(
                      tsTypeExpr.expression
                    );
                  if (tsExprType.isClass()) {
                    self.incrementCounters(
                      node,
                      NodeType.InterfaceExtendsClass
                    );
                  } else if (tsExprType.isClassOrInterface()) {
                    let props = tsExprType.getProperties();
                    for (let p of props) {
                      let propName = p.name;
                      if (p.declarations) {
                        let decl: ts.Declaration = p.declarations[0];
                        if (decl.kind === ts.SyntaxKind.MethodSignature) {
                          self.countInterfaceExtendsDifferentPropertyTypes(
                            node,
                            prop2type,
                            p.name,
                            (decl as ts.MethodSignature).type
                          );
                        } else if (
                          decl.kind === ts.SyntaxKind.MethodDeclaration
                        ) {
                          self.countInterfaceExtendsDifferentPropertyTypes(
                            node,
                            prop2type,
                            p.name,
                            (decl as ts.MethodDeclaration).type
                          );
                        } else if (
                          decl.kind === ts.SyntaxKind.PropertyDeclaration
                        ) {
                          self.countInterfaceExtendsDifferentPropertyTypes(
                            node,
                            prop2type,
                            p.name,
                            (decl as ts.PropertyDeclaration).type
                          );
                        } else if (
                          decl.kind == ts.SyntaxKind.PropertySignature
                        ) {
                          self.countInterfaceExtendsDifferentPropertyTypes(
                            node,
                            prop2type,
                            p.name,
                            (decl as ts.PropertySignature).type
                          );
                        }
                      }
                    }
                  }
                }
              }
            }
          }

          for (let tsTypeElem of interfaceNode.members) {
            if (tsTypeElem.questionToken) {
              self.incrementCounters(
                tsTypeElem,
                NodeType.InterfaceOptionalProp
              );
            }
          }

          self.countDeclarationsWithDuplicateName(
            TypeScriptLinter.tsTypeChecker.getSymbolAtLocation(
              interfaceNode.name
            ),
            interfaceNode
          );

          let tsInterfaceModifiers = ts.getModifiers(interfaceNode);
          if (
            Utils.hasModifier(
              tsInterfaceModifiers,
              ts.SyntaxKind.ExportKeyword
            ) &&
            Utils.hasModifier(
              tsInterfaceModifiers,
              ts.SyntaxKind.DefaultKeyword
            )
          )
            self.incrementCounters(node, NodeType.DefaultExport);

          self.countOverloadedFunctions(interfaceNode.members);

          break;

        case ts.SyntaxKind.IndexSignature:
          self.incrementCounters(node, NodeType.IndexMember);
          break;

        case ts.SyntaxKind.WithStatement:
          self.incrementCounters(node, NodeType.WithStatement);
          break;

        case ts.SyntaxKind.ThrowStatement:
          let throwStmt = node as ts.ThrowStatement;
          let throwExprType = TypeScriptLinter.tsTypeChecker.getTypeAtLocation(
            throwStmt.expression
          );

          if (
            !throwExprType.isClassOrInterface() ||
            !self.typeHierarchyHasTypeError(throwExprType)
          )
            self.incrementCounters(node, NodeType.ThrowStatement);

          break;

        case ts.SyntaxKind.IndexedAccessType:
          self.incrementCounters(node, NodeType.IndexedAccessType);
          break;

        case ts.SyntaxKind.UndefinedKeyword:
          self.incrementCounters(node, NodeType.UndefinedType);
          break;

        case ts.SyntaxKind.UnknownKeyword:
          self.incrementCounters(node, NodeType.UnknownType);
          break;

        case ts.SyntaxKind.ForStatement:
          let tsForStmt = node as ts.ForStatement;

          let tsForInit = tsForStmt.initializer;
          if (
            tsForInit &&
            (ts.isArrayLiteralExpression(tsForInit) ||
              ts.isObjectLiteralExpression(tsForInit))
          )
            self.incrementCounters(tsForInit, NodeType.DestructuringAssignment);

          break;

        case ts.SyntaxKind.ForInStatement:
          let tsForInStmt = node as ts.ForInStatement;

          let tsForInInit = tsForInStmt.initializer;
          if (
            ts.isArrayLiteralExpression(tsForInInit) ||
            ts.isObjectLiteralExpression(tsForInInit)
          )
            self.incrementCounters(
              tsForInInit,
              NodeType.DestructuringAssignment
            );

          self.incrementCounters(node, NodeType.ForInStatement);
          break;

        case ts.SyntaxKind.ForOfStatement:
          let tsForOfStmt = node as ts.ForOfStatement;

          let tsForOfInit = tsForOfStmt.initializer;
          if (
            ts.isArrayLiteralExpression(tsForOfInit) ||
            ts.isObjectLiteralExpression(tsForOfInit)
          )
            self.incrementCounters(
              tsForOfInit,
              NodeType.DestructuringAssignment
            );

          let expr = tsForOfStmt.expression;
          let exprType = TypeScriptLinter.tsTypeChecker.getTypeAtLocation(expr);
          let exprTypeNode = TypeScriptLinter.tsTypeChecker.typeToTypeNode(
            exprType,
            undefined,
            ts.NodeBuilderFlags.None
          );
          if (
            !(
              ts.isArrayLiteralExpression(expr) ||
              Utils.isArrayNotTupleType(exprTypeNode)
            )
          ) {
            self.incrementCounters(node, NodeType.ForOfNonArray);
          }

          break;

        case ts.SyntaxKind.InKeyword:
          self.incrementCounters(node, NodeType.InOperator);
          break;

        case ts.SyntaxKind.SpreadElement:
          self.incrementCounters(node, NodeType.SpreadOperator);
          break;

        case ts.SyntaxKind.SpreadAssignment:
          self.incrementCounters(node, NodeType.SpreadAssignment);
          break;

        case ts.SyntaxKind.TypeOperator:
          if (node.getFullText().trim().startsWith("keyof"))
            self.incrementCounters(node, NodeType.KeyOfOperator);
          if (node.getFullText().trim().startsWith("readonly"))
            self.incrementCounters(node, NodeType.ReadonlyArr);
          break;

        case ts.SyntaxKind.ImportDeclaration:
          let importDeclNode = node as ts.ImportDeclaration;
          let expr_ = importDeclNode.moduleSpecifier;
          if (expr_.kind === ts.SyntaxKind.StringLiteral) {
            if (!importDeclNode.importClause) {
              self.incrementCounters(node, NodeType.ImportFromPath);
            }

            let text = expr_.getText();
            if (text.endsWith('.js"') || text.endsWith(".js'")) {
              self.incrementCounters(node, NodeType.JSExtensionInModuleIdent);
            }

            if (importDeclNode.assertClause) {
              self.incrementCounters(
                importDeclNode.assertClause,
                NodeType.ImportAssertion
              );
            }
          }
          break;

        case ts.SyntaxKind.LiteralType:
          let tsLiteralType = node as ts.LiteralTypeNode;
          if (ts.isStringLiteral(tsLiteralType.literal))
            self.incrementCounters(node, NodeType.StringLiteralType);

          break;

        case ts.SyntaxKind.PropertyAccessExpression:
          let propertyAccessNode = node as ts.PropertyAccessExpression;

          if (self.isObjectRuntimeCheck(propertyAccessNode))
            self.incrementCounters(node, NodeType.ObjectRuntimeCheck);

          if (self.isIIFEasNamespace(propertyAccessNode))
            self.incrementCounters(node, NodeType.IifeAsNamespace);

          if (self.isPrototypePropertyAccess(propertyAccessNode))
            self.incrementCounters(propertyAccessNode.name, NodeType.Prototype);

          break;

        case ts.SyntaxKind.PropertyAssignment:
        case ts.SyntaxKind.PropertyDeclaration:
          let tsPropertyNode = node as
            | ts.PropertyAssignment
            | ts.PropertyDeclaration;
          if (
            (tsPropertyNode.name &&
              tsPropertyNode.name.kind === ts.SyntaxKind.NumericLiteral) ||
            tsPropertyNode.name.kind === ts.SyntaxKind.StringLiteral
          )
            self.incrementCounters(node, NodeType.LiteralAsPropertyName);

          break;

        case ts.SyntaxKind.FunctionExpression:
          self.incrementCounters(node, NodeType.FunctionExpression);

          let funcExpr = node as ts.FunctionExpression;
          if (funcExpr.typeParameters && funcExpr.typeParameters.length > 0) {
            self.incrementCounters(node, NodeType.LambdaWithTypeParameters);
          }

          if (funcExpr.asteriskToken)
            self.incrementCounters(node, NodeType.GeneratorFunction);

          if (self.scopeContainsThis(funcExpr.body))
            self.incrementCounters(node, NodeType.FunctionContainsThis);

          break;

        case ts.SyntaxKind.ArrowFunction:
          let arrowFunc = node as ts.ArrowFunction;

          let hasOmittedType = !arrowFunc.type;
          for (let param of arrowFunc.parameters) {
            hasOmittedType ||= !param.type;
          }

          if (hasOmittedType) {
            self.incrementCounters(
              node,
              NodeType.ArrowFunctionWithOmittedTypes
            );
          }

          if (arrowFunc.typeParameters && arrowFunc.typeParameters.length > 0) {
            self.incrementCounters(node, NodeType.LambdaWithTypeParameters);
          }

          break;

        case ts.SyntaxKind.ClassExpression:
          let tsClassExpr = node as ts.ClassExpression;
          self.incrementCounters(node, NodeType.ClassExpression);
          self.countOverloadedConstructors(tsClassExpr);
          self.countOverloadedFunctions(tsClassExpr.members);

          break;

        case ts.SyntaxKind.TypeParameter:
          let typeParameterNode = node as ts.TypeParameterDeclaration;
          if (typeParameterNode.default)
            self.incrementCounters(
              node,
              NodeType.TypeParameterWithDefaultValue
            );

          break;

        case ts.SyntaxKind.IfStatement:
          let tsIfStatement = node as ts.IfStatement;
          let tsIfExprType = TypeScriptLinter.tsTypeChecker.getTypeAtLocation(
            tsIfStatement.expression
          );
          if (!(tsIfExprType.getFlags() & ts.TypeFlags.BooleanLike))
            self.incrementCounters(node, NodeType.IfWithNonBoolean);

          self.checkExprForDynamicTypeCheck(tsIfStatement.expression);

          break;

        case ts.SyntaxKind.DoStatement:
          let tsDoStatement = node as ts.DoStatement;
          let tsDoExprType = TypeScriptLinter.tsTypeChecker.getTypeAtLocation(
            tsDoStatement.expression
          );
          if (!(tsDoExprType.getFlags() & ts.TypeFlags.BooleanLike))
            self.incrementCounters(node, NodeType.DoWithNonBoolean);

          break;

        case ts.SyntaxKind.WhileStatement:
          let tsWhileStatement = node as ts.WhileStatement;
          let tsWhileExprType =
            TypeScriptLinter.tsTypeChecker.getTypeAtLocation(
              tsWhileStatement.expression
            );
          if (!(tsWhileExprType.getFlags() & ts.TypeFlags.BooleanLike))
            self.incrementCounters(node, NodeType.WhileWithNonBoolean);

          break;

        case ts.SyntaxKind.FunctionDeclaration:
          let tsFunctionDeclaration = node as ts.FunctionDeclaration;
          if (!tsFunctionDeclaration.type)
            self.incrementCounters(node, NodeType.FuncWithoutReturnType);

          if (tsFunctionDeclaration.name)
            self.countDeclarationsWithDuplicateName(
              TypeScriptLinter.tsTypeChecker.getSymbolAtLocation(
                tsFunctionDeclaration.name
              ),
              tsFunctionDeclaration
            );

          let tsParams: ts.NodeArray<ts.ParameterDeclaration> =
            tsFunctionDeclaration.parameters;
          for (let tsParam of tsParams) {
            if (tsParam.questionToken)
              self.incrementCounters(tsParam, NodeType.FuncOptionalParams);
          }

          if (
            tsFunctionDeclaration.body &&
            self.scopeContainsThis(tsFunctionDeclaration.body)
          ) {
            self.incrementCounters(node, NodeType.FunctionContainsThis);
          }

          if (
            !ts.isSourceFile(tsFunctionDeclaration.parent) &&
            !ts.isModuleBlock(tsFunctionDeclaration.parent)
          )
            self.incrementCounters(
              tsFunctionDeclaration,
              NodeType.LocalFunction
            );

          if (tsFunctionDeclaration.asteriskToken)
            self.incrementCounters(node, NodeType.GeneratorFunction);

          let tsFuncModifiers = ts.getModifiers(tsFunctionDeclaration);
          if (
            Utils.hasModifier(tsFuncModifiers, ts.SyntaxKind.ExportKeyword) &&
            Utils.hasModifier(tsFuncModifiers, ts.SyntaxKind.DefaultKeyword)
          )
            self.incrementCounters(node, NodeType.DefaultExport);

          break;

        case ts.SyntaxKind.PrefixUnaryExpression:
          let tsUnaryArithm = node as ts.PrefixUnaryExpression;
          let tsUnaryOp = tsUnaryArithm.operator;
          if (
            tsUnaryOp === ts.SyntaxKind.PlusToken ||
            tsUnaryOp === ts.SyntaxKind.MinusToken ||
            tsUnaryOp === ts.SyntaxKind.TildeToken
          ) {
            let tsOperatndType =
              TypeScriptLinter.tsTypeChecker.getTypeAtLocation(
                tsUnaryArithm.operand
              );
            if (!(tsOperatndType.getFlags() & ts.TypeFlags.NumberLike))
              self.incrementCounters(node, NodeType.UnaryArithmNotNumber);
          } else if (tsUnaryOp === ts.SyntaxKind.ExclamationToken) {
            let tsOperatndType =
              TypeScriptLinter.tsTypeChecker.getTypeAtLocation(
                tsUnaryArithm.operand
              );
            if (!(tsOperatndType.getFlags() & ts.TypeFlags.BooleanLike))
              self.incrementCounters(node, NodeType.LogNotWithNotBool);
          }

          break;

        case ts.SyntaxKind.BinaryExpression:
          let tsBinaryExpr = node as ts.BinaryExpression;
          let tsLhsExpr = tsBinaryExpr.left;

          if (Utils.isAssignmentOperator(tsBinaryExpr.operatorToken)) {
            if (
              ts.isObjectLiteralExpression(tsLhsExpr) ||
              ts.isArrayLiteralExpression(tsLhsExpr)
            ) {
              self.incrementCounters(node, NodeType.DestructuringAssignment);
            }

            if (ts.isPropertyAccessExpression(tsLhsExpr)) {
              let tsLhsSymbol =
                TypeScriptLinter.tsTypeChecker.getSymbolAtLocation(tsLhsExpr);
              let tsLhsBaseSymbol =
                TypeScriptLinter.tsTypeChecker.getSymbolAtLocation(
                  tsLhsExpr.expression
                );
              if (
                Utils.isMethodAssignment(tsLhsSymbol) &&
                (tsLhsBaseSymbol.flags & ts.SymbolFlags.Function) !== 0
              ) {
                self.incrementCounters(
                  tsLhsExpr,
                  NodeType.PropertyDeclOnFunction
                );
              }
            }
          }

          let leftOperandType =
            TypeScriptLinter.tsTypeChecker.getTypeAtLocation(tsLhsExpr);
          let rightOperandType =
            TypeScriptLinter.tsTypeChecker.getTypeAtLocation(
              tsBinaryExpr.right
            );

          if (
            tsBinaryExpr.operatorToken.kind ===
              ts.SyntaxKind.AmpersandAmpersandToken ||
            tsBinaryExpr.operatorToken.kind === ts.SyntaxKind.BarBarToken
          ) {
            if (
              !(
                Utils.isBooleanType(leftOperandType) &&
                Utils.isBooleanType(rightOperandType)
              )
            )
              self.incrementCounters(node, NodeType.LogicalWithNonBoolean);
          } else if (
            tsBinaryExpr.operatorToken.kind === ts.SyntaxKind.PlusToken
          ) {
            if (
              Utils.isNumberType(leftOperandType) &&
              Utils.isNumberType(rightOperandType)
            ) {
              break;
            } else if (
              Utils.isStringType(leftOperandType) ||
              Utils.isStringType(rightOperandType)
            ) {
              break;
            } else self.incrementCounters(node, NodeType.AddWithWrongType);
          } else if (
            tsBinaryExpr.operatorToken.kind === ts.SyntaxKind.AmpersandToken ||
            tsBinaryExpr.operatorToken.kind === ts.SyntaxKind.BarToken ||
            tsBinaryExpr.operatorToken.kind === ts.SyntaxKind.CaretToken ||
            tsBinaryExpr.operatorToken.kind ===
              ts.SyntaxKind.LessThanLessThanToken ||
            tsBinaryExpr.operatorToken.kind ===
              ts.SyntaxKind.GreaterThanGreaterThanToken ||
            tsBinaryExpr.operatorToken.kind ===
              ts.SyntaxKind.GreaterThanGreaterThanGreaterThanToken
          ) {
            if (
              !(
                Utils.isNumberType(leftOperandType) &&
                Utils.isNumberType(rightOperandType)
              )
            )
              self.incrementCounters(node, NodeType.BitOpWithWrongType);
          } else if (
            tsBinaryExpr.operatorToken.kind === ts.SyntaxKind.CommaToken
          ) {
            // CommaOpertor is allowed in 'for' statement initalizer and incrementor
            let tsExprNode: ts.Node = tsBinaryExpr;
            let tsParentNode = tsExprNode.parent;
            while (
              tsParentNode &&
              tsParentNode.kind === ts.SyntaxKind.BinaryExpression
            ) {
              tsExprNode = tsParentNode;
              tsParentNode = tsExprNode.parent;
            }
            if (
              tsParentNode &&
              tsParentNode.kind === ts.SyntaxKind.ForStatement
            ) {
              let tsForNode = tsParentNode as ts.ForStatement;
              if (
                tsExprNode === tsForNode.initializer ||
                tsExprNode === tsForNode.incrementor
              ) {
                break;
              }
            }
            self.incrementCounters(node, NodeType.CommaOperator);
          } else if (
            tsBinaryExpr.operatorToken.kind === ts.SyntaxKind.InstanceOfKeyword
          ) {
            let leftExpr = Utils.unwrapParenthesizedExpression(
              tsBinaryExpr.left
            );
            let leftSymbol =
              TypeScriptLinter.tsTypeChecker.getSymbolAtLocation(leftExpr);
            let leftType =
              TypeScriptLinter.tsTypeChecker.getTypeAtLocation(leftExpr);
            // In STS, the left-hand side expression may be of any reference type, otherwise a compile-time error occurs.
            // In addition, the left operand in STS cannot be a type.
            if (
              ts.isTypeNode(leftExpr) ||
              !Utils.isReferenceType(leftOperandType) ||
              Utils.isTypeSymbol(leftSymbol)
            ) {
              self.incrementCounters(node, NodeType.InstanceofUnsupported);
            }
          }

          break;

        case ts.SyntaxKind.VariableDeclarationList:
          let varDeclFlags = ts.getCombinedNodeFlags(node);
          if (!(varDeclFlags & (ts.NodeFlags.Let | ts.NodeFlags.Const)))
            self.incrementCounters(node, NodeType.VarDeclaration);

          break;

        case ts.SyntaxKind.VariableDeclaration:
          let tsVarDecl = node as ts.VariableDeclaration;

          if (
            ts.isArrayBindingPattern(tsVarDecl.name) ||
            ts.isObjectBindingPattern(tsVarDecl.name)
          )
            self.incrementCounters(node, NodeType.DestructuringDeclaration);

          // Check variable declaration for duplicate name.
          let visitBindingPatternNames = (tsBindingName: ts.BindingName) => {
            if (ts.isIdentifier(tsBindingName))
              // The syntax kind of the declaration is defined here by the parent of 'BindingName' node.
              self.countDeclarationsWithDuplicateName(
                TypeScriptLinter.tsTypeChecker.getSymbolAtLocation(
                  tsBindingName
                ),
                tsBindingName,
                tsBindingName.parent.kind
              );
            else {
              for (const tsBindingElem of tsBindingName.elements) {
                if (ts.isOmittedExpression(tsBindingElem)) continue;

                visitBindingPatternNames(tsBindingElem.name);
              }
            }
          };

          if (tsVarDecl.exclamationToken)
            self.incrementCounters(node, NodeType.DefiniteAssignment);

          visitBindingPatternNames(tsVarDecl.name);

          break;

        case ts.SyntaxKind.IntersectionType:
          self.incrementCounters(node, NodeType.IntersectionType);
          break;

        case ts.SyntaxKind.TypeLiteral:
          self.incrementCounters(node, NodeType.ObjectTypeLiteral);
          break;

        case ts.SyntaxKind.CatchClause:
          let tsCatch = node as ts.CatchClause;
          if (tsCatch.variableDeclaration && tsCatch.variableDeclaration.type) {
            // In TS catch clause doesn't permit specification of the exception varible type except 'any' or 'unknown'.
            // It is not compatible with STS 'catch' where the exception varilab has to be of type 'Exception' or derived from it.
            // So each 'catch' which has explicite type for the exception object goes to problems in strict mode.
            self.incrementCounters(node, NodeType.CatchWithUnsupportedType);
          }
          break;

        case ts.SyntaxKind.ClassDeclaration:
          let tsClassDecl = node as ts.ClassDeclaration;
          if (tsClassDecl.name) {
            self.countDeclarationsWithDuplicateName(
              TypeScriptLinter.tsTypeChecker.getSymbolAtLocation(
                tsClassDecl.name
              ),
              tsClassDecl
            );
          }

          self.countClassMembersWithDuplicateName(tsClassDecl);

          if (tsClassDecl.heritageClauses) {
            for (const hClause of tsClassDecl.heritageClauses) {
              if (
                hClause &&
                hClause.token === ts.SyntaxKind.ImplementsKeyword
              ) {
                for (const tsTypeExpr of hClause.types) {
                  let tsExprType =
                    TypeScriptLinter.tsTypeChecker.getTypeAtLocation(
                      tsTypeExpr.expression
                    );
                  if (tsExprType.isClass())
                    self.incrementCounters(
                      tsTypeExpr,
                      NodeType.ImplementsClass
                    );
                }
              }
            }
          }

          let tsClassModifiers = ts.getModifiers(tsClassDecl);
          if (
            Utils.hasModifier(tsClassModifiers, ts.SyntaxKind.ExportKeyword) &&
            Utils.hasModifier(tsClassModifiers, ts.SyntaxKind.DefaultKeyword)
          )
            self.incrementCounters(node, NodeType.DefaultExport);

          self.countOverloadedConstructors(tsClassDecl);
          self.countOverloadedFunctions(tsClassDecl.members);

          break;

        case ts.SyntaxKind.ModuleDeclaration:
          let tsModuleDecl = node as ts.ModuleDeclaration;
          self.countDeclarationsWithDuplicateName(
            TypeScriptLinter.tsTypeChecker.getSymbolAtLocation(
              tsModuleDecl.name
            ),
            tsModuleDecl
          );

          let tsModuleBody = tsModuleDecl.body;
          let tsModifiers = ts.getModifiers(tsModuleDecl);
          if (tsModuleBody) {
            if (ts.isModuleBlock(tsModuleBody)) {
              for (const tsModuleStmt of tsModuleBody.statements) {
                switch (tsModuleStmt.kind) {
                  case ts.SyntaxKind.VariableStatement:
                  case ts.SyntaxKind.FunctionDeclaration:
                  case ts.SyntaxKind.ClassDeclaration:
                  case ts.SyntaxKind.InterfaceDeclaration:
                  case ts.SyntaxKind.TypeAliasDeclaration:
                  case ts.SyntaxKind.EnumDeclaration:
                  // Nested namespace declarations are prohibited
                  // but there is no cookbook recipe for it!
                  case ts.SyntaxKind.ModuleDeclaration:
                    break;
                  default:
                    self.incrementCounters(
                      tsModuleStmt,
                      NodeType.NonDeclarationInNamespace
                    );
                    break;
                }
              }

              self.countOverloadedFunctions(tsModuleBody.statements);
            }
          } else if (
            Utils.hasModifier(tsModifiers, ts.SyntaxKind.DeclareKeyword)
          ) {
            self.incrementCounters(
              tsModuleDecl,
              NodeType.ShorthandAmbientModuleDecl
            );
          }

          if (
            ts.isStringLiteral(tsModuleDecl.name) &&
            tsModuleDecl.name.text.includes("*")
          ) {
            self.incrementCounters(
              tsModuleDecl,
              NodeType.WildcardsInModuleName
            );
          }

          break;

        case ts.SyntaxKind.TypeAliasDeclaration:
          let tsTypeAlias = node as ts.TypeAliasDeclaration;
          self.countDeclarationsWithDuplicateName(
            TypeScriptLinter.tsTypeChecker.getSymbolAtLocation(
              tsTypeAlias.name
            ),
            tsTypeAlias
          );
          break;

        case ts.SyntaxKind.ImportClause:
          let tsImportClause = node as ts.ImportClause;
          if (tsImportClause.name)
            self.countDeclarationsWithDuplicateName(
              TypeScriptLinter.tsTypeChecker.getSymbolAtLocation(
                tsImportClause.name
              ),
              tsImportClause
            );

          if (tsImportClause.isTypeOnly)
            self.incrementCounters(node, NodeType.TypeOnlyImport);

          break;

        case ts.SyntaxKind.ImportSpecifier:
          let tsImportSpecifier = node as ts.ImportSpecifier;
          self.countDeclarationsWithDuplicateName(
            TypeScriptLinter.tsTypeChecker.getSymbolAtLocation(
              tsImportSpecifier.name
            ),
            tsImportSpecifier
          );

          if (
            tsImportSpecifier.propertyName &&
            tsImportSpecifier.propertyName.text === "default"
          )
            self.incrementCounters(node, NodeType.DefaultImport);

          if (tsImportSpecifier.isTypeOnly)
            self.incrementCounters(node, NodeType.TypeOnlyImport);

          break;

        case ts.SyntaxKind.NamespaceImport:
          let tsNamespaceImport = node as ts.NamespaceImport;
          self.countDeclarationsWithDuplicateName(
            TypeScriptLinter.tsTypeChecker.getSymbolAtLocation(
              tsNamespaceImport.name
            ),
            tsNamespaceImport
          );
          break;

        case ts.SyntaxKind.ConstructorType:
        case ts.SyntaxKind.ConstructSignature:
          self.incrementCounters(node, NodeType.ConstructorType);
          break;

        case ts.SyntaxKind.CallSignature:
          self.incrementCounters(node, NodeType.CallSignature);
          break;

        case ts.SyntaxKind.NoSubstitutionTemplateLiteral:
        case ts.SyntaxKind.TemplateExpression:
          self.incrementCounters(node, NodeType.TemplateLiteral);
          break;

        case ts.SyntaxKind.TypeAssertionExpression:
          let tsTypeAssertion = node as ts.TypeAssertion;

          if (tsTypeAssertion.type.getText() === "const") {
            self.incrementCounters(tsTypeAssertion, NodeType.ConstAssertion);
          } else {
            self.incrementCounters(node, NodeType.TypeAssertion);
          }

          break;

        case ts.SyntaxKind.MethodDeclaration:
          let tsMethodDecl = node as ts.MethodDeclaration;
          if (!tsMethodDecl.type)
            self.incrementCounters(node, NodeType.FuncWithoutReturnType);

          if (tsMethodDecl.asteriskToken)
            self.incrementCounters(node, NodeType.GeneratorFunction);

          break;

        case ts.SyntaxKind.ClassStaticBlockDeclaration:
          if (ts.isClassDeclaration(node.parent)) {
            let tsClassDecl = node.parent as ts.ClassDeclaration;
            let className: string = "";
            if (tsClassDecl.name)
              // May be undefined in `export default class { ... }`.
              className = tsClassDecl.name.text;

            if (self.staticBlocks.has(className)) {
              self.incrementCounters(node, NodeType.MultipleStaticBlocks);
            } else {
              self.staticBlocks.add(className);
            }
          }

          break;

        case ts.SyntaxKind.PrivateIdentifier:
          self.incrementCounters(node, NodeType.PrivateIdentifier);
          break;

        case ts.SyntaxKind.SwitchStatement:
          let tsSwitchStmt = node as ts.SwitchStatement;

          let tsSwitchExprType =
            TypeScriptLinter.tsTypeChecker.getTypeAtLocation(
              tsSwitchStmt.expression
            );
          if (
            !(
              tsSwitchExprType.getFlags() &
              (ts.TypeFlags.NumberLike | ts.TypeFlags.StringLike)
            ) &&
            !Utils.isEnumType(tsSwitchExprType)
          ) {
            self.incrementCounters(
              tsSwitchStmt.expression,
              NodeType.SwitchSelectorInvalidType
            );
          }

          for (const tsCaseClause of tsSwitchStmt.caseBlock.clauses) {
            if (ts.isCaseClause(tsCaseClause)) {
              let tsCaseExpr = tsCaseClause.expression;
              let tsCaseExprType =
                TypeScriptLinter.tsTypeChecker.getTypeAtLocation(tsCaseExpr);
              if (
                !(
                  ts.isNumericLiteral(tsCaseExpr) ||
                  ts.isStringLiteralLike(tsCaseExpr) ||
                  tsCaseExprType.flags & ts.TypeFlags.EnumLike
                )
              ) {
                self.incrementCounters(
                  tsCaseExpr,
                  NodeType.CaseExpressionNonConst
                );
              }
            }
          }

          break;

        case ts.SyntaxKind.ConditionalType:
          self.incrementCounters(node, NodeType.ConditionalType);
          break;

        case ts.SyntaxKind.MappedType:
          self.incrementCounters(node, NodeType.MappedType);
          break;

        case ts.SyntaxKind.Identifier:
          let tsIdentifier = node as ts.Identifier;
          let tsIdentSym =
            TypeScriptLinter.tsTypeChecker.getSymbolAtLocation(tsIdentifier);
          if (
            tsIdentSym &&
            (tsIdentSym.getFlags() & ts.SymbolFlags.Module) !== 0 &&
            (tsIdentSym.getFlags() & ts.SymbolFlags.Variable) === 0 &&
            !ts.isModuleDeclaration(tsIdentifier.parent)
          ) {
            // If module name is duplicated by another declaration, this increases the possibility
            // of finding a lot of false positives. Thus, do not check further in that case.
            if (
              !Utils.symbolHasDuplicateName(
                tsIdentSym,
                ts.SyntaxKind.ModuleDeclaration
              )
            ) {
              // If module name is the right-most name of Property Access chain or Qualified name,
              // or it's a separate identifier expression, then module is being referenced as an object.
              let tsIdentParent: ts.Node = tsIdentifier;

              while (
                ts.isPropertyAccessExpression(tsIdentParent.parent) ||
                ts.isQualifiedName(tsIdentParent.parent)
              )
                tsIdentParent = tsIdentParent.parent;

              if (
                (!ts.isPropertyAccessExpression(tsIdentParent) &&
                  !ts.isQualifiedName(tsIdentParent)) ||
                (ts.isPropertyAccessExpression(tsIdentParent) &&
                  tsIdentifier === tsIdentParent.name) ||
                (ts.isQualifiedName(tsIdentParent) &&
                  tsIdentifier === tsIdentParent.right)
              )
                self.incrementCounters(node, NodeType.NamespaceAsObject);
            }
          }

          if (
            tsIdentSym &&
            (tsIdentSym.flags & ts.SymbolFlags.Module) !== 0 &&
            (tsIdentSym.flags & ts.SymbolFlags.Transient) !== 0 &&
            tsIdentifier.text === "globalThis"
          ) {
            self.incrementCounters(node, NodeType.GlobalThis);
          }

          if (self.isObjectRuntimeCheck(tsIdentifier))
            self.incrementCounters(node, NodeType.ObjectRuntimeCheck);

          break;

        case ts.SyntaxKind.ElementAccessExpression:
          let tsElementAccessExpr = node as ts.ElementAccessExpression;
          let tsIndexExpr = tsElementAccessExpr.argumentExpression;

          let tsElemAccessBaseExprType =
            TypeScriptLinter.tsTypeChecker.getTypeAtLocation(
              tsElementAccessExpr.expression
            );
          let tsElemAccessBaseExprTypeNode =
            TypeScriptLinter.tsTypeChecker.typeToTypeNode(
              tsElemAccessBaseExprType,
              undefined,
              ts.NodeBuilderFlags.None
            );
          let tsElemAccessExprType =
            TypeScriptLinter.tsTypeChecker.getTypeAtLocation(
              tsElementAccessExpr.argumentExpression
            );
          if (
            (tsElemAccessBaseExprType.isClassOrInterface() ||
              Utils.isThisOrSuperExpr(tsElementAccessExpr.expression) ||
              Utils.isEnumType(tsElemAccessBaseExprType)) &&
            (ts.isStringLiteral(tsIndexExpr) ||
              ts.isNumericLiteral(tsIndexExpr))
          )
            break;
          if (
            !(
              Utils.isArrayNotTupleType(tsElemAccessBaseExprTypeNode) &&
              Utils.isNumberLikeType(tsElemAccessExprType)
            )
          ) {
            self.incrementCounters(node, NodeType.PropertyAccessByIndex);
          }

          break;

        case ts.SyntaxKind.JsxElement:
        case ts.SyntaxKind.JsxSelfClosingElement:
          self.incrementCounters(node, NodeType.JsxElement);
          break;

        case ts.SyntaxKind.EnumMember:
          let tsEnumMember = node as ts.EnumMember;
          if (tsEnumMember.initializer)
            self.incrementCounters(node, NodeType.EnumMemberWithInitializer);
          break;

        case ts.SyntaxKind.ClassStaticBlockDeclaration:
          if (ts.isClassDeclaration(node.parent)) {
            let tsClassDecl = node.parent as ts.ClassDeclaration;
            let className: string = "";
            if (tsClassDecl.name)
              // May be undefined in `export default class { ... }`.
              className = tsClassDecl.name.text;

            if (self.staticBlocks.has(className)) {
              self.incrementCounters(node, NodeType.MultipleStaticBlocks);
            } else {
              self.staticBlocks.add(className);
            }
          }

          break;

        case ts.SyntaxKind.Decorator:
          let tsDecorator = node as ts.Decorator;
          let tsDecoratorName = tsDecorator.getText();

          let n = self.decorators.get(tsDecoratorName);
          if (n) n++;
          else n = 1;

          self.decorators.set(tsDecoratorName, n);
          break;

        case ts.SyntaxKind.ExportDeclaration:
          let tsExportDecl = node as ts.ExportDeclaration;

          if (tsExportDecl.isTypeOnly)
            self.incrementCounters(node, NodeType.TypeOnlyExport);

          if (tsExportDecl.moduleSpecifier)
            self.incrementCounters(node, NodeType.ReExporting);

          break;

        case ts.SyntaxKind.NamedExports:
          self.incrementCounters(node, NodeType.ExportListDeclaration);
          break;

        case ts.SyntaxKind.ExportSpecifier:
          let tsExportSpecifier = node as ts.ExportSpecifier;

          if (tsExportSpecifier.propertyName)
            self.incrementCounters(node, NodeType.ExportRenaming);

          if (tsExportSpecifier.isTypeOnly)
            self.incrementCounters(node, NodeType.TypeOnlyExport);

          break;

        case ts.SyntaxKind.ExportAssignment:
          let tsExportAssignment = node as ts.ExportAssignment;

          if (tsExportAssignment.isExportEquals)
            self.incrementCounters(node, NodeType.ExportAssignment);
          else self.incrementCounters(node, NodeType.DefaultExport);

          break;

        case ts.SyntaxKind.ImportEqualsDeclaration:
          self.incrementCounters(node, NodeType.ImportAssignment);
          break;

        case ts.SyntaxKind.NamespaceExportDeclaration:
          self.incrementCounters(node, NodeType.UMDModuleDefinition);
          break;

        case ts.SyntaxKind.CallExpression:
          let tsCallExpr = node as ts.CallExpression;

          if (tsCallExpr.expression.kind === ts.SyntaxKind.ImportKeyword) {
            self.incrementCounters(node, NodeType.DynamicImport);

            let tsArgs = tsCallExpr.arguments;
            if (tsArgs.length > 1 && ts.isObjectLiteralExpression(tsArgs[1])) {
              for (let tsProp of tsArgs[1].properties) {
                if (
                  ts.isPropertyAssignment(tsProp) ||
                  ts.isShorthandPropertyAssignment(tsProp)
                ) {
                  if (tsProp.name.getText() === "assert") {
                    self.incrementCounters(tsProp, NodeType.ImportAssertion);
                    break;
                  }
                }
              }
            }
          }

          let tsCallSignature =
            TypeScriptLinter.tsTypeChecker.getResolvedSignature(tsCallExpr);
          if (tsCallSignature) {
            let tsSignDecl = tsCallSignature.getDeclaration();
            if (
              tsSignDecl &&
              tsSignDecl.typeParameters &&
              tsSignDecl.typeParameters.length > 0 &&
              (!tsCallExpr.typeArguments ||
                tsCallExpr.typeArguments.length !==
                  tsSignDecl.typeParameters.length)
            )
              self.incrementCounters(node, NodeType.GenericCallNoTypeArgs);
          }

          let tsExpr = tsCallExpr.expression;
          if (
            ts.isPropertyAccessExpression(tsExpr) &&
            (tsExpr.name.text === "apply" ||
              tsExpr.name.text === "bind" ||
              tsExpr.name.text === "call")
          ) {
            let tsSymbol = TypeScriptLinter.tsTypeChecker.getSymbolAtLocation(
              tsExpr.expression
            );
            if (Utils.isFunctionOrMethod(tsSymbol)) {
              self.incrementCounters(node, NodeType.FunctionApplyBindCall);
            }
          }

          break;

        case ts.SyntaxKind.NewExpression:
          let tsNewExpr = node as ts.NewExpression;

          let tsNewExprType =
            TypeScriptLinter.tsTypeChecker.getTypeAtLocation(tsNewExpr);
          if (
            (tsNewExprType.getFlags() & ts.TypeFlags.Object) !== 0 &&
            ((tsNewExprType as ts.ObjectType).objectFlags &
              ts.ObjectFlags.Reference) !==
              0
          ) {
            let tsTargetType = (tsNewExprType as ts.TypeReference).target;
            if (
              tsTargetType.typeParameters &&
              tsTargetType.typeParameters.length > 0 &&
              (!tsNewExpr.typeArguments ||
                tsNewExpr.typeArguments.length !==
                  tsTargetType.typeParameters.length)
            )
              self.incrementCounters(node, NodeType.GenericCallNoTypeArgs);
          }

          if (
            Utils.isGenericArrayType(
              TypeScriptLinter.tsTypeChecker.getTypeAtLocation(tsNewExpr)
            )
          )
            self.incrementCounters(node, NodeType.GenericArrayType);

          break;

        case ts.SyntaxKind.AsExpression:
          let tsAsExpr = node as ts.AsExpression;

          if (tsAsExpr.type.getText() === "const") {
            self.incrementCounters(node, NodeType.ConstAssertion);
          }

          break;
        case ts.SyntaxKind.TypeReference:
          let tsTypeRef = node as ts.TypeReferenceNode;

          if (
            Utils.isGenericArrayType(
              TypeScriptLinter.tsTypeChecker.getTypeAtLocation(tsTypeRef)
            )
          )
            self.incrementCounters(node, NodeType.GenericArrayType);

          if (
            ts.isIdentifier(tsTypeRef.typeName) &&
            self.standardUtilityTypes.includes(tsTypeRef.typeName.text)
          )
            self.incrementCounters(node, NodeType.UtilityType);

          break;

        case ts.SyntaxKind.SourceFile:
          let tsSrcFile = node as ts.SourceFile;
          self.countOverloadedFunctions(tsSrcFile.statements);
          break;

        case ts.SyntaxKind.Block:
          let tsBlock = node as ts.Block;
          self.countOverloadedFunctions(tsBlock.statements);
          break;

        case ts.SyntaxKind.MetaProperty:
          let tsMetaProperty = node as ts.MetaProperty;
          if (tsMetaProperty.name.text === "target")
            self.incrementCounters(node, NodeType.NewTarget);

          break;

        case ts.SyntaxKind.NonNullExpression:
          self.incrementCounters(node, NodeType.DefiniteAssignment);
          break;

        default:
          break;
      }

      // Increase common Node counter.
      TypeScriptLinter.nodeCntr++;

      ts.forEachChild(node, visitTSNode);
    }
  }

  private countInterfaceExtendsDifferentPropertyTypes(
    node: ts.Node,
    prop2type: Map<string, string>,
    propName: string,
    type: ts.TypeNode
  ) {
    if (type) {
      let methodType = type.getText();
      let propType = prop2type.get(propName);
      if (!propType) {
        prop2type.set(propName, methodType);
      } else if (propType !== methodType) {
        this.incrementCounters(node, NodeType.IntefaceExtendDifProps);
      }
    }
  }

  private typeHierarchyHasTypeError(type: ts.Type): boolean {
    let symbol = type.getSymbol();
    if (symbol?.getName() === "Error") {
      return true;
    } else {
      let baseTypes = type.getBaseTypes();
      if (baseTypes) {
        for (let baseType of baseTypes) {
          if (this.typeHierarchyHasTypeError(baseType)) return true;
        }
      }
    }

    return false;
  }

  private countDeclarationsWithDuplicateName(
    symbol: ts.Symbol,
    tsDeclNode: ts.Node,
    tsDeclKind?: ts.SyntaxKind
  ): void {
    // Sanity check.
    if (!symbol) return;

    // If specific declaration kind is provided, check against it.
    // Otherwise, use syntax kind of corresponding declaration node.
    if (Utils.symbolHasDuplicateName(symbol, tsDeclKind ?? tsDeclNode.kind)) {
      this.incrementCounters(tsDeclNode, NodeType.DeclWithDuplicateName);
    }
  }

  private countClassMembersWithDuplicateName(
    tsClassDecl: ts.ClassDeclaration
  ): void {
    for (const tsCurrentMember of tsClassDecl.members) {
      if (
        !tsCurrentMember.name ||
        !(
          ts.isIdentifier(tsCurrentMember.name) ||
          ts.isPrivateIdentifier(tsCurrentMember.name)
        )
      )
        continue;

      for (const tsClassMember of tsClassDecl.members) {
        if (tsCurrentMember === tsClassMember) continue;

        if (
          !tsClassMember.name ||
          !(
            ts.isIdentifier(tsClassMember.name) ||
            ts.isPrivateIdentifier(tsClassMember.name)
          )
        )
          continue;

        if (
          ts.isIdentifier(tsCurrentMember.name) &&
          ts.isPrivateIdentifier(tsClassMember.name) &&
          tsCurrentMember.name.text === tsClassMember.name.text.substring(1)
        ) {
          this.incrementCounters(
            tsCurrentMember,
            NodeType.DeclWithDuplicateName
          );
          break;
        }

        if (
          ts.isPrivateIdentifier(tsCurrentMember.name) &&
          ts.isIdentifier(tsClassMember.name) &&
          tsCurrentMember.name.text.substring(1) === tsClassMember.name.text
        ) {
          this.incrementCounters(
            tsCurrentMember,
            NodeType.DeclWithDuplicateName
          );
          break;
        }
      }
    }
  }

  private scopeContainsThis(tsNode: ts.Node): boolean {
    let found = false;

    function visitNode(tsNode: ts.Node) {
      // Stop visiting child nodes if finished searching.
      if (found) return;

      if (tsNode.kind === ts.SyntaxKind.ThisKeyword) {
        found = true;
        return;
      }

      // Visit children nodes. Skip any local declaration that defines
      // its own scope as it needs to be checked separately.
      if (
        !ts.isClassDeclaration(tsNode) &&
        !ts.isClassExpression(tsNode) &&
        !ts.isModuleDeclaration(tsNode) &&
        !ts.isFunctionDeclaration(tsNode) &&
        !ts.isFunctionExpression(tsNode)
      ) {
        tsNode.forEachChild(visitNode);
      }
    }
    visitNode(tsNode);

    return found;
  }

  private checkPropertyAccessForDynamicTypeCheck(
    tsPropAccess: ts.PropertyAccessExpression
  ): void {
    let childName = tsPropAccess.name.text;
    let objType = TypeScriptLinter.tsTypeChecker.getTypeAtLocation(
      tsPropAccess.expression
    );
    let props = objType.getProperties();
    let found = false;
    for (let prop of props) {
      if (prop.getName() === childName) {
        found = true;
        break;
      }
    }

    if (!found) this.incrementCounters(tsPropAccess, NodeType.DynamicTypeCheck);
  }

  private checkExprForDynamicTypeCheck(tsExpr: ts.Expression): void {
    if (ts.isPropertyAccessExpression(tsExpr)) {
      this.checkPropertyAccessForDynamicTypeCheck(
        tsExpr as ts.PropertyAccessExpression
      );
    } else if (ts.isPropertyAccessChain(tsExpr)) {
      let tsPropAccessChain = tsExpr as ts.PropertyAccessChain;
      this.checkPropertyAccessForDynamicTypeCheck(tsPropAccessChain);
      this.checkExprForDynamicTypeCheck(tsPropAccessChain.expression);
    } else if (ts.isBinaryExpression(tsExpr)) {
      let tsBinExpr = tsExpr as ts.BinaryExpression;
      this.checkExprForDynamicTypeCheck(tsBinExpr.left);
      this.checkExprForDynamicTypeCheck(tsBinExpr.right);
    }
  }

  private isObjectRuntimeCheck(
    tsExpr: ts.Identifier | ts.PropertyAccessExpression
  ): boolean {
    // Get parent node of the expression, unwrap enclosing parentheses if needed.
    let tsExprParent = tsExpr.parent;
    while (ts.isParenthesizedExpression(tsExprParent))
      tsExprParent = tsExprParent.parent;

    // If object reference is not a boolean type and is used
    // in a boolean context (if statement, ternary operator, while loop, etc.),
    // then this is a object runtime check.
    let tsExprType = TypeScriptLinter.tsTypeChecker.getTypeAtLocation(tsExpr);
    return (
      tsExprType &&
      !(tsExprType.getFlags() & ts.TypeFlags.BooleanLike) &&
      ((ts.isIfStatement(tsExprParent) &&
        tsExpr ===
          Utils.unwrapParenthesizedExpression(tsExprParent.expression)) ||
        (ts.isWhileStatement(tsExprParent) &&
          tsExpr ===
            Utils.unwrapParenthesizedExpression(tsExprParent.expression)) ||
        (ts.isDoStatement(tsExprParent) &&
          tsExpr ===
            Utils.unwrapParenthesizedExpression(tsExprParent.expression)) ||
        (ts.isForStatement(tsExprParent) &&
          tsExprParent.condition &&
          tsExpr ===
            Utils.unwrapParenthesizedExpression(tsExprParent.condition)) ||
        (ts.isConditionalExpression(tsExprParent) &&
          tsExpr ===
            Utils.unwrapParenthesizedExpression(tsExprParent.condition)) ||
        (ts.isBinaryExpression(tsExprParent) &&
          (tsExprParent.operatorToken.kind ===
            ts.SyntaxKind.AmpersandAmpersandToken ||
            tsExprParent.operatorToken.kind === ts.SyntaxKind.BarBarToken)) ||
        (ts.isPrefixUnaryExpression(tsExprParent) &&
          tsExprParent.operator === ts.SyntaxKind.ExclamationToken))
    );
  }

  private isIIFEasNamespace(tsExpr: ts.PropertyAccessExpression): boolean {
    const nameSymbol = TypeScriptLinter.tsTypeChecker.getSymbolAtLocation(
      tsExpr.name
    );
    if (!nameSymbol) {
      const leftHandSymbol = TypeScriptLinter.tsTypeChecker.getSymbolAtLocation(
        tsExpr.expression
      );
      if (leftHandSymbol) {
        let decls = leftHandSymbol.getDeclarations();
        if (decls && decls.length === 1) {
          let leftHandDecl = decls[0];
          if (ts.isVariableDeclaration(leftHandDecl)) {
            let varDecl = leftHandDecl as ts.VariableDeclaration;
            if (varDecl.initializer) {
              if (ts.isCallExpression(varDecl.initializer)) {
                let callExpr = varDecl.initializer as ts.CallExpression;
                let expr = Utils.unwrapParenthesizedExpression(
                  callExpr.expression
                );
                if (ts.isFunctionExpression(expr)) return true;
              }
            }
          }
        }
      }
    }

    return false;
  }

  private countOverloadedFunctions(
    tsStatementsOrDecls: ts.NodeArray<ts.Node>
  ): void {
    let tsFunctionMap: Map<string, ts.Node[]> = new Map<string, ts.Node[]>();

    for (let tsChildNode of tsStatementsOrDecls) {
      if (
        (ts.isFunctionDeclaration(tsChildNode) ||
          ts.isMethodDeclaration(tsChildNode) ||
          ts.isMethodSignature(tsChildNode)) &&
        tsChildNode.name &&
        ts.isIdentifier(tsChildNode.name)
      ) {
        let tsFunName = tsChildNode.name.text;
        if (!tsFunctionMap.has(tsFunName)) {
          tsFunctionMap.set(tsFunName, [tsChildNode]);
        } else {
          tsFunctionMap.get(tsFunName).push(tsChildNode);
        }
      }
    }

    for (let tsFunDecls of tsFunctionMap.values()) {
      if (tsFunDecls.length > 1) {
        for (let tsFunDecl of tsFunDecls) {
          this.incrementCounters(tsFunDecl, NodeType.FunctionOverload);
        }
      }
    }
  }

  private countOverloadedConstructors(tsClassDecl: ts.ClassLikeDeclaration) {
    let tsClassCtors: ts.ClassElement[] = [];

    for (let tsClassElem of tsClassDecl.members) {
      if (tsClassElem.kind === ts.SyntaxKind.Constructor)
        tsClassCtors.push(tsClassElem);
    }

    if (tsClassCtors.length > 1) {
      for (let tsClassCtor of tsClassCtors) {
        this.incrementCounters(tsClassCtor, NodeType.ConstructorOverload);
      }
    }
  }

  private isPrototypePropertyAccess(
    tsPropertyAccess: ts.PropertyAccessExpression
  ): boolean {
    if (
      !(
        ts.isIdentifier(tsPropertyAccess.name) &&
        tsPropertyAccess.name.text === "prototype"
      )
    )
      return false;

    // Check if property symbol is 'Prototype'
    let propAccessSym =
      TypeScriptLinter.tsTypeChecker.getSymbolAtLocation(tsPropertyAccess);
    if (Utils.isPrototypeSymbol(propAccessSym)) return true;

    // Check if symbol of LHS-expression is Class or Function.
    let tsBaseExpr = tsPropertyAccess.expression;
    let baseExprSym =
      TypeScriptLinter.tsTypeChecker.getSymbolAtLocation(tsBaseExpr);
    if (Utils.isTypeSymbol(baseExprSym) || Utils.isFunctionSymbol(baseExprSym))
      return true;

    // Check if type of LHS expression Function type or Any type.
    // The latter check is to cover cases with multiple prototype
    // chain (as the 'Prototype' property should be 'Any' type):
    //      X.prototype.prototype.prototype = ...
    let baseExprType =
      TypeScriptLinter.tsTypeChecker.getTypeAtLocation(tsBaseExpr);
    let baseExprTypeNode = TypeScriptLinter.tsTypeChecker.typeToTypeNode(
      baseExprType,
      undefined,
      ts.NodeBuilderFlags.None
    );
    if (
      ts.isFunctionTypeNode(baseExprTypeNode) ||
      Utils.isAnyType(baseExprType)
    )
      return true;

    return false;
  }

  public lint(): any {
    this.CountTSNodes(this.tsSourceFile);
    return null;
  }
}
