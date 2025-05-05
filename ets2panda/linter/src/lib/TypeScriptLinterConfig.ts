/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

export class TypeScriptLinterConfig {

  /*
   * The SyntaxKind enum defines additional elements at the end of the enum
   * that serve as markers (FirstX/LastX). Those elements are initialized
   * with indices of the previously defined elements. As result, the enum
   * may return incorrect name for a certain kind index (e.g. 'FirstStatement'
   * instead of 'VariableStatement').
   * The following code creates a map with correct syntax kind names.
   * It can be used when need to print name of syntax kind of certain
   * AST node in diagnostic messages.
   */
  static tsSyntaxKindNames: string[] = [];

  static {
    TypeScriptLinterConfig.initTsSyntaxKindNames();
  }

  private static initTsSyntaxKindNames(): void {
    const keys = Object.keys(ts.SyntaxKind);
    const values = Object.values(ts.SyntaxKind);

    for (let i = 0; i < values.length; i++) {
      const val = values[i];
      const kindNum = typeof val === 'string' ? parseInt(val) : val;
      if (kindNum && !TypeScriptLinterConfig.tsSyntaxKindNames[kindNum]) {
        TypeScriptLinterConfig.tsSyntaxKindNames[kindNum] = keys[i];
      }
    }
  }

  // must detect terminals during parsing
  static terminalTokens: Set<ts.SyntaxKind> = new Set([
    ts.SyntaxKind.CloseBracketToken,
    ts.SyntaxKind.OpenBracketToken,
    ts.SyntaxKind.CloseParenToken,
    ts.SyntaxKind.OpenParenToken,
    ts.SyntaxKind.CloseBraceToken,
    ts.SyntaxKind.OpenBraceToken,
    ts.SyntaxKind.CommaToken,
    ts.SyntaxKind.SemicolonToken,
    ts.SyntaxKind.QuestionDotToken,
    ts.SyntaxKind.DotDotDotToken,
    ts.SyntaxKind.DotToken,
    ts.SyntaxKind.MinusMinusToken,
    ts.SyntaxKind.PlusPlusToken,
    ts.SyntaxKind.PercentToken,
    ts.SyntaxKind.SlashToken,
    ts.SyntaxKind.AsteriskAsteriskToken,
    ts.SyntaxKind.AsteriskToken,
    ts.SyntaxKind.MinusToken,
    ts.SyntaxKind.PlusToken,
    ts.SyntaxKind.EqualsGreaterThanToken,
    ts.SyntaxKind.ExclamationEqualsEqualsToken,
    ts.SyntaxKind.ExclamationEqualsToken,
    ts.SyntaxKind.EqualsEqualsToken,
    ts.SyntaxKind.EqualsEqualsEqualsToken,
    ts.SyntaxKind.GreaterThanEqualsToken,
    ts.SyntaxKind.LessThanEqualsToken,
    ts.SyntaxKind.GreaterThanGreaterThanGreaterThanToken,
    ts.SyntaxKind.GreaterThanGreaterThanToken,
    ts.SyntaxKind.GreaterThanToken,
    ts.SyntaxKind.LessThanSlashToken,
    ts.SyntaxKind.LessThanToken,
    ts.SyntaxKind.LessThanLessThanToken,
    ts.SyntaxKind.HashToken,
    ts.SyntaxKind.BacktickToken,
    ts.SyntaxKind.AtToken,
    ts.SyntaxKind.ColonToken,
    ts.SyntaxKind.QuestionToken,
    ts.SyntaxKind.QuestionQuestionToken,
    ts.SyntaxKind.BarBarToken,
    ts.SyntaxKind.AmpersandAmpersandToken,
    ts.SyntaxKind.TildeToken,
    ts.SyntaxKind.ExclamationToken,
    ts.SyntaxKind.CaretToken,
    ts.SyntaxKind.BarToken,
    ts.SyntaxKind.AmpersandToken,
    ts.SyntaxKind.CaretEqualsToken,
    ts.SyntaxKind.BarEqualsToken,
    ts.SyntaxKind.AmpersandEqualsToken,
    ts.SyntaxKind.GreaterThanGreaterThanGreaterThanEqualsToken,
    ts.SyntaxKind.GreaterThanGreaterThanEqualsToken,
    ts.SyntaxKind.LessThanLessThanEqualsToken,
    ts.SyntaxKind.PercentEqualsToken,
    ts.SyntaxKind.SlashEqualsToken,
    ts.SyntaxKind.AsteriskAsteriskEqualsToken,
    ts.SyntaxKind.AsteriskEqualsToken,
    ts.SyntaxKind.MinusEqualsToken,
    ts.SyntaxKind.PlusEqualsToken,
    ts.SyntaxKind.EqualsToken,
    ts.SyntaxKind.MultiLineCommentTrivia,
    ts.SyntaxKind.SingleLineCommentTrivia,
    ts.SyntaxKind.WhitespaceTrivia,
    ts.SyntaxKind.NewLineTrivia,
    ts.SyntaxKind.EndOfFileToken,
    ts.SyntaxKind.ConflictMarkerTrivia,
    ts.SyntaxKind.ShebangTrivia
  ]);

  // tokens which can be reported without additional parsing
  static incrementOnlyTokens: Map<ts.SyntaxKind, FaultID> = new Map([
    [ts.SyntaxKind.AnyKeyword, FaultID.AnyType],
    [ts.SyntaxKind.SymbolKeyword, FaultID.SymbolType],
    [ts.SyntaxKind.ThisType, FaultID.ThisType],
    [ts.SyntaxKind.TypeQuery, FaultID.TypeQuery],
    [ts.SyntaxKind.DeleteExpression, FaultID.DeleteOperator],
    [ts.SyntaxKind.TypePredicate, FaultID.IsOperator],
    [ts.SyntaxKind.YieldExpression, FaultID.YieldExpression],
    [ts.SyntaxKind.WithStatement, FaultID.WithStatement],
    [ts.SyntaxKind.IndexedAccessType, FaultID.IndexedAccessType],
    [ts.SyntaxKind.UnknownKeyword, FaultID.UnknownType],
    [ts.SyntaxKind.CallSignature, FaultID.CallSignature],
    [ts.SyntaxKind.IntersectionType, FaultID.IntersectionType],
    [ts.SyntaxKind.ConstructorType, FaultID.ConstructorFuncs],
    [ts.SyntaxKind.ConditionalType, FaultID.ConditionalType],
    [ts.SyntaxKind.MappedType, FaultID.MappedType],
    [ts.SyntaxKind.JsxElement, FaultID.JsxElement],
    [ts.SyntaxKind.JsxSelfClosingElement, FaultID.JsxElement],
    [ts.SyntaxKind.ImportEqualsDeclaration, FaultID.ImportAssignment],
    [ts.SyntaxKind.NamespaceExportDeclaration, FaultID.UMDModuleDefinition],
    [ts.SyntaxKind.ClassExpression, FaultID.ClassExpression]
  ]);
}
