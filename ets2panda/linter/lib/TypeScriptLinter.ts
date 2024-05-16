/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
import { TsUtils } from './utils/TsUtils';
import { FaultID } from './Problems';
import { faultsAttrs } from './FaultAttrs';
import { faultDesc } from './FaultDesc';
import { cookBookMsg, cookBookTag } from './CookBookMsg';
import { LinterConfig } from './TypeScriptLinterConfig';
import type { Autofix } from './autofixes/Autofixer';
import { Autofixer } from './autofixes/Autofixer';
import type { ProblemInfo } from './ProblemInfo';
import { ProblemSeverity } from './ProblemSeverity';
import { Logger } from './Logger';
import { LIMITED_STD_GLOBAL_FUNC } from './utils/consts/LimitedStdGlobalFunc';
import { LIMITED_STD_OBJECT_API } from './utils/consts/LimitedStdObjectAPI';
import { LIMITED_STD_REFLECT_API } from './utils/consts/LimitedStdReflectAPI';
import { LIMITED_STD_PROXYHANDLER_API } from './utils/consts/LimitedStdProxyHandlerAPI';
import { ALLOWED_STD_SYMBOL_API } from './utils/consts/AllowedStdSymbolAPI';
import {
  NON_INITIALIZABLE_PROPERTY_DECORATORS,
  NON_INITIALIZABLE_PROPERTY_CLASS_DECORATORS
} from './utils/consts/NonInitializablePropertyDecorators';
import { NON_RETURN_FUNCTION_DECORATORS } from './utils/consts/NonReturnFunctionDecorators';
import { LIMITED_STANDARD_UTILITY_TYPES } from './utils/consts/LimitedStandardUtilityTypes';
import { PROPERTY_HAS_NO_INITIALIZER_ERROR_CODE } from './utils/consts/PropertyHasNoInitializerErrorCode';
import { FUNCTION_HAS_NO_RETURN_ERROR_CODE } from './utils/consts/FunctionHasNoReturnErrorCode';
import { identiferUseInValueContext } from './utils/functions/identiferUseInValueContext';
import { hasPredecessor } from './utils/functions/HasPredecessor';
import { isStructDeclaration, isStruct } from './utils/functions/IsStruct';
import { isAssignmentOperator } from './utils/functions/isAssignmentOperator';
import type { IncrementalLintInfo } from './IncrementalLintInfo';
import { cookBookRefToFixTitle } from './autofixes/AutofixTitles';
import { isStdLibraryType } from './utils/functions/IsStdLibrary';
import type { ReportAutofixCallback } from './autofixes/ReportAutofixCallback';
import type { DiagnosticChecker } from './utils/functions/DiagnosticChecker';
import {
  ARGUMENT_OF_TYPE_0_IS_NOT_ASSIGNABLE_TO_PARAMETER_OF_TYPE_1_ERROR_CODE,
  NO_OVERLOAD_MATCHES_THIS_CALL_ERROR_CODE,
  TYPE_0_IS_NOT_ASSIGNABLE_TO_TYPE_1_ERROR_CODE,
  LibraryTypeCallDiagnosticChecker
} from './utils/functions/LibraryTypeCallDiagnosticChecker';
import { forEachNodeInSubtree } from './utils/functions/ForEachNodeInSubtree';
import type { IsEtsFileCallback } from './IsEtsFileCallback';
import { SupportedStdCallApiChecker } from './utils/functions/SupportedStdCallAPI';

export function consoleLog(...args: unknown[]): void {
  if (TypeScriptLinter.ideMode) {
    return;
  }
  let outLine = '';
  for (let k = 0; k < args.length; k++) {
    outLine += `${args[k]} `;
  }
  Logger.info(outLine);
}

export class TypeScriptLinter {
  totalVisitedNodes: number = 0;
  nodeCounters: number[] = [];
  lineCounters: number[] = [];

  totalErrorLines: number = 0;
  errorLineNumbersString: string = '';
  totalWarningLines: number = 0;
  warningLineNumbersString: string = '';

  problemsInfos: ProblemInfo[] = [];

  tsUtils: TsUtils;

  currentErrorLine: number;
  currentWarningLine: number;
  walkedComments: Set<number>;
  libraryTypeCallDiagnosticChecker: LibraryTypeCallDiagnosticChecker;
  supportedStdCallApiChecker: SupportedStdCallApiChecker;

  autofixer: Autofixer | undefined;

  private sourceFile?: ts.SourceFile;
  private static sharedModulesCache: Map<string, boolean>;
  static filteredDiagnosticMessages: Set<ts.DiagnosticMessageChain>;
  static ideMode: boolean = false;
  static testMode: boolean = false;
  static useRelaxedRules = false;

  static advancedClassChecks = false;

  static initGlobals(): void {
    TypeScriptLinter.filteredDiagnosticMessages = new Set<ts.DiagnosticMessageChain>();
    TypeScriptLinter.sharedModulesCache = new Map<string, boolean>();
  }

  private initEtsHandlers(): void {

    /*
     * some syntax elements are ArkTs-specific and are only implemented inside patched
     * compiler, so we initialize those handlers if corresponding properties do exist
     */
    const etsComponentExpression: ts.SyntaxKind | undefined = (ts.SyntaxKind as any).EtsComponentExpression;
    if (etsComponentExpression) {
      this.handlersMap.set(etsComponentExpression, this.handleEtsComponentExpression);
    }
  }

  private initCounters(): void {
    for (let i = 0; i < FaultID.LAST_ID; i++) {
      this.nodeCounters[i] = 0;
      this.lineCounters[i] = 0;
    }
  }

  constructor(
    private readonly tsTypeChecker: ts.TypeChecker,
    private readonly enableAutofix: boolean,
    private readonly cancellationToken?: ts.CancellationToken,
    private readonly incrementalLintInfo?: IncrementalLintInfo,
    private readonly tscStrictDiagnostics?: Map<string, ts.Diagnostic[]>,
    private readonly reportAutofixCb?: ReportAutofixCallback,
    private readonly isEtsFileCb?: IsEtsFileCallback
  ) {
    this.tsUtils = new TsUtils(this.tsTypeChecker, TypeScriptLinter.testMode, TypeScriptLinter.advancedClassChecks);
    this.currentErrorLine = 0;
    this.currentWarningLine = 0;
    this.walkedComments = new Set<number>();
    this.libraryTypeCallDiagnosticChecker = new LibraryTypeCallDiagnosticChecker(
      TypeScriptLinter.filteredDiagnosticMessages
    );
    this.supportedStdCallApiChecker = new SupportedStdCallApiChecker(this.tsUtils, this.tsTypeChecker);

    this.initEtsHandlers();
    this.initCounters();
  }

  readonly handlersMap = new Map([
    [ts.SyntaxKind.ObjectLiteralExpression, this.handleObjectLiteralExpression],
    [ts.SyntaxKind.ArrayLiteralExpression, this.handleArrayLiteralExpression],
    [ts.SyntaxKind.Parameter, this.handleParameter],
    [ts.SyntaxKind.EnumDeclaration, this.handleEnumDeclaration],
    [ts.SyntaxKind.InterfaceDeclaration, this.handleInterfaceDeclaration],
    [ts.SyntaxKind.ThrowStatement, this.handleThrowStatement],
    [ts.SyntaxKind.ImportClause, this.handleImportClause],
    [ts.SyntaxKind.ForStatement, this.handleForStatement],
    [ts.SyntaxKind.ForInStatement, this.handleForInStatement],
    [ts.SyntaxKind.ForOfStatement, this.handleForOfStatement],
    [ts.SyntaxKind.ImportDeclaration, this.handleImportDeclaration],
    [ts.SyntaxKind.PropertyAccessExpression, this.handlePropertyAccessExpression],
    [ts.SyntaxKind.PropertyDeclaration, this.handlePropertyDeclaration],
    [ts.SyntaxKind.PropertyAssignment, this.handlePropertyAssignment],
    [ts.SyntaxKind.PropertySignature, this.handlePropertySignature],
    [ts.SyntaxKind.FunctionExpression, this.handleFunctionExpression],
    [ts.SyntaxKind.ArrowFunction, this.handleArrowFunction],
    [ts.SyntaxKind.CatchClause, this.handleCatchClause],
    [ts.SyntaxKind.FunctionDeclaration, this.handleFunctionDeclaration],
    [ts.SyntaxKind.PrefixUnaryExpression, this.handlePrefixUnaryExpression],
    [ts.SyntaxKind.BinaryExpression, this.handleBinaryExpression],
    [ts.SyntaxKind.VariableDeclarationList, this.handleVariableDeclarationList],
    [ts.SyntaxKind.VariableDeclaration, this.handleVariableDeclaration],
    [ts.SyntaxKind.ClassDeclaration, this.handleClassDeclaration],
    [ts.SyntaxKind.ModuleDeclaration, this.handleModuleDeclaration],
    [ts.SyntaxKind.TypeAliasDeclaration, this.handleTypeAliasDeclaration],
    [ts.SyntaxKind.ImportSpecifier, this.handleImportSpecifier],
    [ts.SyntaxKind.NamespaceImport, this.handleNamespaceImport],
    [ts.SyntaxKind.TypeAssertionExpression, this.handleTypeAssertionExpression],
    [ts.SyntaxKind.MethodDeclaration, this.handleMethodDeclaration],
    [ts.SyntaxKind.MethodSignature, this.handleMethodSignature],
    [ts.SyntaxKind.ClassStaticBlockDeclaration, this.handleClassStaticBlockDeclaration],
    [ts.SyntaxKind.Identifier, this.handleIdentifier],
    [ts.SyntaxKind.ElementAccessExpression, this.handleElementAccessExpression],
    [ts.SyntaxKind.EnumMember, this.handleEnumMember],
    [ts.SyntaxKind.TypeReference, this.handleTypeReference],
    [ts.SyntaxKind.ExportAssignment, this.handleExportAssignment],
    [ts.SyntaxKind.CallExpression, this.handleCallExpression],
    [ts.SyntaxKind.MetaProperty, this.handleMetaProperty],
    [ts.SyntaxKind.NewExpression, this.handleNewExpression],
    [ts.SyntaxKind.AsExpression, this.handleAsExpression],
    [ts.SyntaxKind.SpreadElement, this.handleSpreadOp],
    [ts.SyntaxKind.SpreadAssignment, this.handleSpreadOp],
    [ts.SyntaxKind.GetAccessor, this.handleGetAccessor],
    [ts.SyntaxKind.SetAccessor, this.handleSetAccessor],
    [ts.SyntaxKind.ConstructSignature, this.handleConstructSignature],
    [ts.SyntaxKind.ExpressionWithTypeArguments, this.handleExpressionWithTypeArguments],
    [ts.SyntaxKind.ComputedPropertyName, this.handleComputedPropertyName],
    [ts.SyntaxKind.Constructor, this.handleConstructorDeclaration],
    [ts.SyntaxKind.PrivateIdentifier, this.handlePrivateIdentifier],
    [ts.SyntaxKind.IndexSignature, this.handleIndexSignature],
    [ts.SyntaxKind.TypeLiteral, this.handleTypeLiteral],
    [ts.SyntaxKind.ExportKeyword, this.handleExportKeyword],
    [ts.SyntaxKind.ExportDeclaration, this.handleExportDeclaration]
  ]);

  private getLineAndCharacterOfNode(node: ts.Node | ts.CommentRange): ts.LineAndCharacter {
    const startPos = TsUtils.getStartPos(node);
    const { line, character } = this.sourceFile!.getLineAndCharacterOfPosition(startPos);
    // TSC counts lines and columns from zero
    return { line: line + 1, character: character + 1 };
  }

  incrementCounters(
    node: ts.Node | ts.CommentRange,
    faultId: number,
    autofix?: Autofix[]
  ): void {
    this.nodeCounters[faultId]++;
    const { line, character } = this.getLineAndCharacterOfNode(node);
    if (TypeScriptLinter.ideMode) {
      this.incrementCountersIdeMode(node, faultId, autofix);
    } else {
      const faultDescr = faultDesc[faultId];
      const faultType = LinterConfig.tsSyntaxKindNames[node.kind];
      Logger.info(
        `Warning: ${this.sourceFile!.fileName} (${line}, ${character}): ${faultDescr ? faultDescr : faultType}`
      );
    }
    this.lineCounters[faultId]++;
    switch (faultsAttrs[faultId].severity) {
      case ProblemSeverity.ERROR: {
        this.currentErrorLine = line;
        ++this.totalErrorLines;
        this.errorLineNumbersString += line + ', ';
        break;
      }
      case ProblemSeverity.WARNING: {
        if (line === this.currentWarningLine) {
          break;
        }
        this.currentWarningLine = line;
        ++this.totalWarningLines;
        this.warningLineNumbersString += line + ', ';
        break;
      }
    }
  }

  private incrementCountersIdeMode(
    node: ts.Node | ts.CommentRange,
    faultId: number,
    autofix?: Autofix[]
  ): void {
    if (!TypeScriptLinter.ideMode) {
      return;
    }
    const [startOffset, endOffset] = TsUtils.getHighlightRange(node, faultId);
    const startPos = this.sourceFile!.getLineAndCharacterOfPosition(startOffset);
    const endPos = this.sourceFile!.getLineAndCharacterOfPosition(endOffset);

    const faultDescr = faultDesc[faultId];
    const faultType = LinterConfig.tsSyntaxKindNames[node.kind];

    const cookBookMsgNum = faultsAttrs[faultId] ? faultsAttrs[faultId].cookBookRef : 0;
    const cookBookTg = cookBookTag[cookBookMsgNum];
    const severity = faultsAttrs[faultId]?.severity ?? ProblemSeverity.ERROR;
    const isMsgNumValid = cookBookMsgNum > 0;
    const badNodeInfo: ProblemInfo = {
      line: startPos.line + 1,
      column: startPos.character + 1,
      endLine: endPos.line + 1,
      endColumn: endPos.character + 1,
      start: startOffset,
      end: endOffset,
      type: faultType,
      severity: severity,
      problem: FaultID[faultId],
      suggest: isMsgNumValid ? cookBookMsg[cookBookMsgNum] : '',
      rule: isMsgNumValid && cookBookTg !== '' ? cookBookTg : faultDescr ? faultDescr : faultType,
      ruleTag: cookBookMsgNum,
      autofix: autofix,
      autofixTitle: isMsgNumValid && autofix !== undefined ? cookBookRefToFixTitle.get(cookBookMsgNum) : undefined
    };
    this.problemsInfos.push(badNodeInfo);
    // problems with autofixes might be collected separately
    if (this.reportAutofixCb && badNodeInfo.autofix) {
      this.reportAutofixCb(badNodeInfo);
    }
  }

  private visitSourceFile(sf: ts.SourceFile): void {
    const callback = (node: ts.Node): void => {
      this.totalVisitedNodes++;
      if (isStructDeclaration(node)) {
        // early exit via exception if cancellation was requested
        this.cancellationToken?.throwIfCancellationRequested();
      }
      const incrementedType = LinterConfig.incrementOnlyTokens.get(node.kind);
      if (incrementedType !== undefined) {
        this.incrementCounters(node, incrementedType);
      } else {
        const handler = this.handlersMap.get(node.kind);
        if (handler !== undefined) {

          /*
           * possibly requested cancellation will be checked in a limited number of handlers
           * checked nodes are selected as construct nodes, similar to how TSC does
           */
          handler.call(this, node);
        }
      }
    };
    const stopCondition = (node: ts.Node): boolean => {
      if (!node) {
        return true;
      }
      if (this.incrementalLintInfo?.shouldSkipCheck(node)) {
        return true;
      }
      // Skip synthetic constructor in Struct declaration.
      if (node.parent && isStructDeclaration(node.parent) && ts.isConstructorDeclaration(node)) {
        return true;
      }
      if (LinterConfig.terminalTokens.has(node.kind)) {
        return true;
      }
      return false;
    };
    forEachNodeInSubtree(sf, callback, stopCondition);
  }

  private countInterfaceExtendsDifferentPropertyTypes(
    node: ts.Node,
    prop2type: Map<string, string>,
    propName: string,
    type: ts.TypeNode | undefined
  ): void {
    if (type) {
      const methodType = type.getText();
      const propType = prop2type.get(propName);
      if (!propType) {
        prop2type.set(propName, methodType);
      } else if (propType !== methodType) {
        this.incrementCounters(node, FaultID.IntefaceExtendDifProps);
      }
    }
  }

  private countDeclarationsWithDuplicateName(tsNode: ts.Node, tsDeclNode: ts.Node, tsDeclKind?: ts.SyntaxKind): void {
    const symbol = this.tsTypeChecker.getSymbolAtLocation(tsNode);

    /*
     * If specific declaration kind is provided, check against it.
     * Otherwise, use syntax kind of corresponding declaration node.
     */
    if (!!symbol && TsUtils.symbolHasDuplicateName(symbol, tsDeclKind ?? tsDeclNode.kind)) {
      this.incrementCounters(tsDeclNode, FaultID.DeclWithDuplicateName);
    }
  }

  private countClassMembersWithDuplicateName(tsClassDecl: ts.ClassDeclaration): void {
    for (const currentMember of tsClassDecl.members) {
      if (this.tsUtils.classMemberHasDuplicateName(currentMember, tsClassDecl)) {
        this.incrementCounters(currentMember, FaultID.DeclWithDuplicateName);
      }
    }
  }

  private isPrototypePropertyAccess(
    tsPropertyAccess: ts.PropertyAccessExpression,
    propAccessSym: ts.Symbol | undefined,
    baseExprSym: ts.Symbol | undefined,
    baseExprType: ts.Type
  ): boolean {
    if (!(ts.isIdentifier(tsPropertyAccess.name) && tsPropertyAccess.name.text === 'prototype')) {
      return false;
    }

    // #13600: Relax prototype check when expression comes from interop.
    let curPropAccess: ts.Node = tsPropertyAccess;
    while (curPropAccess && ts.isPropertyAccessExpression(curPropAccess)) {
      const baseExprSym = this.tsUtils.trueSymbolAtLocation(curPropAccess.expression);
      if (this.tsUtils.isLibrarySymbol(baseExprSym)) {
        return false;
      }
      curPropAccess = curPropAccess.expression;
    }

    if (ts.isIdentifier(curPropAccess) && curPropAccess.text !== 'prototype') {
      const type = this.tsTypeChecker.getTypeAtLocation(curPropAccess);
      if (TsUtils.isAnyType(type)) {
        return false;
      }
    }

    // Check if property symbol is 'Prototype'
    if (TsUtils.isPrototypeSymbol(propAccessSym)) {
      return true;
    }
    // Check if symbol of LHS-expression is Class or Function.
    if (TsUtils.isTypeSymbol(baseExprSym) || TsUtils.isFunctionSymbol(baseExprSym)) {
      return true;
    }

    /*
     * Check if type of LHS expression Function type or Any type.
     * The latter check is to cover cases with multiple prototype
     * chain (as the 'Prototype' property should be 'Any' type):
     *      X.prototype.prototype.prototype = ...
     */
    const baseExprTypeNode = this.tsTypeChecker.typeToTypeNode(baseExprType, undefined, ts.NodeBuilderFlags.None);
    return baseExprTypeNode && ts.isFunctionTypeNode(baseExprTypeNode) || TsUtils.isAnyType(baseExprType);
  }

  private interfaceInheritanceLint(node: ts.Node, heritageClauses: ts.NodeArray<ts.HeritageClause>): void {
    for (const hClause of heritageClauses) {
      if (hClause.token !== ts.SyntaxKind.ExtendsKeyword) {
        continue;
      }
      const prop2type = new Map<string, string>();
      for (const tsTypeExpr of hClause.types) {
        const tsExprType = this.tsTypeChecker.getTypeAtLocation(tsTypeExpr.expression);
        if (tsExprType.isClass()) {
          this.incrementCounters(tsTypeExpr, FaultID.InterfaceExtendsClass);
        } else if (tsExprType.isClassOrInterface()) {
          this.lintForInterfaceExtendsDifferentPorpertyTypes(node, tsExprType, prop2type);
        }
      }
    }
  }

  private lintForInterfaceExtendsDifferentPorpertyTypes(
    node: ts.Node,
    tsExprType: ts.Type,
    prop2type: Map<string, string>
  ): void {
    const props = tsExprType.getProperties();
    for (const p of props) {
      if (!p.declarations) {
        continue;
      }
      const decl: ts.Declaration = p.declarations[0];
      const isPropertyDecl = ts.isPropertyDeclaration(decl) || ts.isPropertyDeclaration(decl);
      const isMethodDecl = ts.isMethodSignature(decl) || ts.isMethodDeclaration(decl);
      if (isMethodDecl || isPropertyDecl) {
        this.countInterfaceExtendsDifferentPropertyTypes(node, prop2type, p.name, decl.type);
      }
    }
  }

  private handleObjectLiteralExpression(node: ts.Node): void {
    const objectLiteralExpr = node as ts.ObjectLiteralExpression;
    // If object literal is a part of destructuring assignment, then don't process it further.
    if (TsUtils.isDestructuringAssignmentLHS(objectLiteralExpr)) {
      return;
    }

    const objectLiteralType = this.tsTypeChecker.getContextualType(objectLiteralExpr);
    if (objectLiteralType && this.tsUtils.typeContainsSendableClassOrInterface(objectLiteralType)) {
      this.incrementCounters(node, FaultID.SendableObjectInitialization);
    } else if (
      // issue 13082: Allow initializing struct instances with object literal.
      !this.tsUtils.isStructObjectInitializer(objectLiteralExpr) &&
      !this.tsUtils.isDynamicLiteralInitializer(objectLiteralExpr) &&
      !this.tsUtils.isObjectLiteralAssignable(objectLiteralType, objectLiteralExpr)
    ) {
      const autofix = this.autofixer?.fixUntypedObjectLiteral(objectLiteralExpr, objectLiteralType);
      this.incrementCounters(node, FaultID.ObjectLiteralNoContextType, autofix);
    }
  }

  private handleArrayLiteralExpression(node: ts.Node): void {

    /*
     * If array literal is a part of destructuring assignment, then
     * don't process it further.
     */
    if (TsUtils.isDestructuringAssignmentLHS(node as ts.ArrayLiteralExpression)) {
      return;
    }
    const arrayLitNode = node as ts.ArrayLiteralExpression;
    let noContextTypeForArrayLiteral = false;

    const arrayLitType = this.tsTypeChecker.getContextualType(arrayLitNode);
    if (arrayLitType && this.tsUtils.typeContainsSendableClassOrInterface(arrayLitType)) {
      this.incrementCounters(node, FaultID.SendableObjectInitialization);
      return;
    }

    /*
     * check that array literal consists of inferrable types
     * e.g. there is no element which is untyped object literals
     */
    const arrayLitElements = arrayLitNode.elements;
    for (const element of arrayLitElements) {
      if (ts.isObjectLiteralExpression(element)) {
        const objectLiteralType = this.tsTypeChecker.getContextualType(element);
        if (
          !this.tsUtils.isDynamicLiteralInitializer(arrayLitNode) &&
          !this.tsUtils.isObjectLiteralAssignable(objectLiteralType, element)
        ) {
          noContextTypeForArrayLiteral = true;
          break;
        }
      }
    }
    if (noContextTypeForArrayLiteral) {
      this.incrementCounters(node, FaultID.ArrayLiteralNoContextType);
    }
  }

  private handleParameter(node: ts.Node): void {
    const tsParam = node as ts.ParameterDeclaration;
    TsUtils.getDecoratorsIfInSendableClass(tsParam)?.forEach((decorator) => {
      this.incrementCounters(decorator, FaultID.SendableClassDecorator);
    });
    this.handleDeclarationDestructuring(tsParam);
    this.handleDeclarationInferredType(tsParam);
  }

  private handleEnumDeclaration(node: ts.Node): void {
    const enumNode = node as ts.EnumDeclaration;
    this.countDeclarationsWithDuplicateName(enumNode.name, enumNode);
    const enumSymbol = this.tsUtils.trueSymbolAtLocation(enumNode.name);
    if (!enumSymbol) {
      return;
    }
    const enumDecls = enumSymbol.getDeclarations();
    if (!enumDecls) {
      return;
    }

    /*
     * Since type checker merges all declarations with the same name
     * into one symbol, we need to check that there's more than one
     * enum declaration related to that specific symbol.
     * See 'countDeclarationsWithDuplicateName' method for details.
     */
    let enumDeclCount = 0;
    const enumDeclsInFile: ts.Declaration[] = [];
    const nodeSrcFile = enumNode.getSourceFile();
    for (const decl of enumDecls) {
      if (decl.kind === ts.SyntaxKind.EnumDeclaration) {
        if (nodeSrcFile === decl.getSourceFile()) {
          enumDeclsInFile.push(decl);
        }
        enumDeclCount++;
      }
    }

    if (enumDeclCount > 1) {
      const autofix = this.autofixer?.fixEnumMerging(enumSymbol, enumDeclsInFile);
      this.incrementCounters(node, FaultID.EnumMerging, autofix);
    }
  }

  private handleInterfaceDeclaration(node: ts.Node): void {
    // early exit via exception if cancellation was requested
    this.cancellationToken?.throwIfCancellationRequested();

    const interfaceNode = node as ts.InterfaceDeclaration;
    const iSymbol = this.tsUtils.trueSymbolAtLocation(interfaceNode.name);
    const iDecls = iSymbol ? iSymbol.getDeclarations() : null;
    if (iDecls) {

      /*
       * Since type checker merges all declarations with the same name
       * into one symbol, we need to check that there's more than one
       * interface declaration related to that specific symbol.
       * See 'countDeclarationsWithDuplicateName' method for details.
       */
      let iDeclCount = 0;
      for (const decl of iDecls) {
        if (decl.kind === ts.SyntaxKind.InterfaceDeclaration) {
          iDeclCount++;
        }
      }
      if (iDeclCount > 1) {
        this.incrementCounters(node, FaultID.InterfaceMerging);
      }
    }
    if (interfaceNode.heritageClauses) {
      this.interfaceInheritanceLint(node, interfaceNode.heritageClauses);
    }
    this.countDeclarationsWithDuplicateName(interfaceNode.name, interfaceNode);
  }

  private handleThrowStatement(node: ts.Node): void {
    const throwStmt = node as ts.ThrowStatement;
    const throwExprType = this.tsTypeChecker.getTypeAtLocation(throwStmt.expression);
    if (
      !throwExprType.isClassOrInterface() ||
      !this.tsUtils.isOrDerivedFrom(throwExprType, this.tsUtils.isStdErrorType)
    ) {
      this.incrementCounters(node, FaultID.ThrowStatement);
    }
  }

  private checkForLoopDestructuring(forInit: ts.ForInitializer): void {
    if (ts.isVariableDeclarationList(forInit) && forInit.declarations.length === 1) {
      const varDecl = forInit.declarations[0];
      if (ts.isArrayBindingPattern(varDecl.name) || ts.isObjectBindingPattern(varDecl.name)) {
        this.incrementCounters(varDecl, FaultID.DestructuringDeclaration);
      }
    }
    if (ts.isArrayLiteralExpression(forInit) || ts.isObjectLiteralExpression(forInit)) {
      this.incrementCounters(forInit, FaultID.DestructuringAssignment);
    }
  }

  private handleForStatement(node: ts.Node): void {
    const tsForStmt = node as ts.ForStatement;
    const tsForInit = tsForStmt.initializer;
    if (tsForInit) {
      this.checkForLoopDestructuring(tsForInit);
    }
  }

  private handleForInStatement(node: ts.Node): void {
    const tsForInStmt = node as ts.ForInStatement;
    const tsForInInit = tsForInStmt.initializer;
    this.checkForLoopDestructuring(tsForInInit);
    this.incrementCounters(node, FaultID.ForInStatement);
  }

  private handleForOfStatement(node: ts.Node): void {
    const tsForOfStmt = node as ts.ForOfStatement;
    const tsForOfInit = tsForOfStmt.initializer;
    this.checkForLoopDestructuring(tsForOfInit);
  }

  private handleImportDeclaration(node: ts.Node): void {
    // early exit via exception if cancellation was requested
    this.cancellationToken?.throwIfCancellationRequested();

    const importDeclNode = node as ts.ImportDeclaration;
    for (const stmt of importDeclNode.parent.statements) {
      if (stmt === importDeclNode) {
        break;
      }
      if (!ts.isImportDeclaration(stmt)) {
        this.incrementCounters(node, FaultID.ImportAfterStatement);
        break;
      }
    }

    const expr1 = importDeclNode.moduleSpecifier;
    if (expr1.kind === ts.SyntaxKind.StringLiteral) {
      if (importDeclNode.assertClause) {
        this.incrementCounters(importDeclNode.assertClause, FaultID.ImportAssertion);
      }
    }

    // handle no side effect import in sendable module
    this.handleSharedModuleNoSideEffectImport(importDeclNode);
  }

  private handleSharedModuleNoSideEffectImport(node : ts.ImportDeclaration):void {
    // check 'use shared'
    if (TypeScriptLinter.inSharedModule(node) && !node.importClause) {
      this.incrementCounters(node, FaultID.SharedNoSideEffectImport);
    }
  }

  private static inSharedModule(node: ts.Node): boolean {
    const sourceFile: ts.SourceFile = node.getSourceFile();
    const modulePath = path.normalize(sourceFile.fileName);
    if (TypeScriptLinter.sharedModulesCache.has(modulePath)) {
      return TypeScriptLinter.sharedModulesCache.get(modulePath)!;
    }
    const isSharedModule: boolean = TsUtils.isSharedModule(sourceFile);
    TypeScriptLinter.sharedModulesCache.set(modulePath, isSharedModule);
    return isSharedModule;
  }

  private handlePropertyAccessExpression(node: ts.Node): void {
    if (ts.isCallExpression(node.parent) && node === node.parent.expression) {
      return;
    }

    const propertyAccessNode = node as ts.PropertyAccessExpression;
    const exprSym = this.tsUtils.trueSymbolAtLocation(propertyAccessNode);
    const baseExprSym = this.tsUtils.trueSymbolAtLocation(propertyAccessNode.expression);
    const baseExprType = this.tsTypeChecker.getTypeAtLocation(propertyAccessNode.expression);

    if (this.isPrototypePropertyAccess(propertyAccessNode, exprSym, baseExprSym, baseExprType)) {
      this.incrementCounters(propertyAccessNode.name, FaultID.Prototype);
    }

    if (!!exprSym && this.tsUtils.isSymbolAPI(exprSym) && !ALLOWED_STD_SYMBOL_API.includes(exprSym.getName())) {
      this.incrementCounters(propertyAccessNode, FaultID.SymbolType);
    }
    if (TypeScriptLinter.advancedClassChecks && this.tsUtils.isClassObjectExpression(propertyAccessNode.expression)) {
      // missing exact rule
      this.incrementCounters(propertyAccessNode.expression, FaultID.ClassAsObject);
    }

    if (!!baseExprSym && TsUtils.symbolHasEsObjectType(baseExprSym)) {
      this.incrementCounters(propertyAccessNode, FaultID.EsObjectType);
    }
  }

  private handlePropertyDeclaration(node: ts.PropertyDeclaration): void {
    const propName = node.name;
    if (!!propName && ts.isNumericLiteral(propName)) {
      const autofix = this.autofixer?.fixLiteralAsPropertyNamePropertyName(propName);
      this.incrementCounters(node, FaultID.LiteralAsPropertyName, autofix);
    }

    const decorators = ts.getDecorators(node);
    this.filterOutDecoratorsDiagnostics(
      decorators,
      NON_INITIALIZABLE_PROPERTY_DECORATORS,
      { begin: propName.getStart(), end: propName.getStart() },
      PROPERTY_HAS_NO_INITIALIZER_ERROR_CODE
    );
    const classDecorators = ts.getDecorators(node.parent);
    const propType = node.type?.getText();
    this.filterOutDecoratorsDiagnostics(
      classDecorators,
      NON_INITIALIZABLE_PROPERTY_CLASS_DECORATORS,
      { begin: propName.getStart(), end: propName.getStart() },
      PROPERTY_HAS_NO_INITIALIZER_ERROR_CODE,
      propType
    );
    this.handleDeclarationInferredType(node);
    this.handleDefiniteAssignmentAssertion(node);
    this.handleSendableClassProperty(node);
  }

  private handleSendableClassProperty(node: ts.PropertyDeclaration): void {
    const typeNode = node.type;
    if (!typeNode) {
      return;
    }
    const classNode = node.parent;
    if (!ts.isClassDeclaration(classNode) || !TsUtils.hasSendableDecorator(classNode)) {
      return;
    }
    TsUtils.getDecoratorsIfInSendableClass(node)?.forEach((decorator) => {
      this.incrementCounters(decorator, FaultID.SendableClassDecorator);
    });
    if (!this.tsUtils.isSendableTypeNode(typeNode)) {
      this.incrementCounters(node, FaultID.SendablePropType);
    }
  }

  private handlePropertyAssignment(node: ts.PropertyAssignment): void {
    const propName = node.name;
    if (!(!!propName && ts.isNumericLiteral(propName))) {
      return;
    }

    /*
     * We can use literals as property names only when creating Record or any interop instances.
     * We can also initialize with constant string literals.
     * Assignment with string enum values is handled in handleComputedPropertyName
     */
    let isRecordObjectInitializer = false;
    let isLibraryType = false;
    let isDynamic = false;
    const objectLiteralType = this.tsTypeChecker.getContextualType(node.parent);
    if (objectLiteralType) {
      isRecordObjectInitializer = this.tsUtils.checkTypeSet(objectLiteralType, this.tsUtils.isStdRecordType);
      isLibraryType = this.tsUtils.isLibraryType(objectLiteralType);
    }

    isDynamic = isLibraryType || this.tsUtils.isDynamicLiteralInitializer(node.parent);
    if (!isRecordObjectInitializer && !isDynamic) {
      const autofix = this.autofixer?.fixLiteralAsPropertyNamePropertyAssignment(node);
      this.incrementCounters(node, FaultID.LiteralAsPropertyName, autofix);
    }
  }

  private handlePropertySignature(node: ts.PropertySignature): void {
    this.handleSendableInterfaceProperty(node);
  }

  private handleSendableInterfaceProperty(node: ts.PropertySignature): void {
    const typeNode = node.type;
    if (!typeNode) {
      return;
    }
    const interfaceNode = node.parent;
    const interfaceNodeType = this.tsTypeChecker.getTypeAtLocation(interfaceNode);
    if (!ts.isInterfaceDeclaration(interfaceNode) || !this.tsUtils.isSendableClassOrInterface(interfaceNodeType)) {
      return;
    }
    if (!this.tsUtils.isSendableTypeNode(typeNode)) {
      this.incrementCounters(node, FaultID.SendablePropType);
    }
  }

  private filterOutDecoratorsDiagnostics(
    decorators: readonly ts.Decorator[] | undefined,
    expectedDecorators: readonly string[],
    range: { begin: number; end: number },
    code: number,
    propType?: string
  ): void {
    // Filter out non-initializable property decorators from strict diagnostics.
    if (this.tscStrictDiagnostics && this.sourceFile) {
      if (
        decorators?.some((decorator) => {
          const decoratorName = TsUtils.getDecoratorName(decorator);
          // special case for property of type CustomDialogController of the @CustomDialog-decorated class
          if (expectedDecorators.includes(NON_INITIALIZABLE_PROPERTY_CLASS_DECORATORS[0])) {
            return expectedDecorators.includes(decoratorName) && propType === 'CustomDialogController';
          }
          return expectedDecorators.includes(decoratorName);
        })
      ) {
        const file = path.normalize(this.sourceFile.fileName);
        const tscDiagnostics = this.tscStrictDiagnostics.get(file);
        if (tscDiagnostics) {
          const filteredDiagnostics = tscDiagnostics.filter((val) => {
            if (val.code !== code) {
              return true;
            }
            if (val.start === undefined) {
              return true;
            }
            if (val.start < range.begin) {
              return true;
            }
            if (val.start > range.end) {
              return true;
            }
            return false;
          });
          this.tscStrictDiagnostics.set(file, filteredDiagnostics);
        }
      }
    }
  }

  private static checkInRange(rangesToFilter: { begin: number; end: number }[], pos: number): boolean {
    for (let i = 0; i < rangesToFilter.length; i++) {
      if (pos >= rangesToFilter[i].begin && pos < rangesToFilter[i].end) {
        return false;
      }
    }
    return true;
  }

  private filterStrictDiagnostics(
    filters: { [code: number]: (pos: number) => boolean },
    diagnosticChecker: DiagnosticChecker
  ): boolean {
    if (!this.tscStrictDiagnostics || !this.sourceFile) {
      return false;
    }
    const file = path.normalize(this.sourceFile.fileName);
    const tscDiagnostics = this.tscStrictDiagnostics.get(file);
    if (!tscDiagnostics) {
      return false;
    }

    const checkDiagnostic = (val: ts.Diagnostic): boolean => {
      const checkInRange = filters[val.code];
      if (!checkInRange) {
        return true;
      }
      if (val.start === undefined || checkInRange(val.start)) {
        return true;
      }
      return diagnosticChecker.checkDiagnosticMessage(val.messageText);
    };

    if (tscDiagnostics.every(checkDiagnostic)) {
      return false;
    }
    this.tscStrictDiagnostics.set(file, tscDiagnostics.filter(checkDiagnostic));
    return true;
  }

  private static isClassLikeOrIface(node: ts.Node): boolean {
    return ts.isClassLike(node) || ts.isInterfaceDeclaration(node);
  }

  private handleFunctionExpression(node: ts.Node): void {
    const funcExpr = node as ts.FunctionExpression;
    const isGenerator = funcExpr.asteriskToken !== undefined;
    const [hasUnfixableReturnType, newRetTypeNode] = this.handleMissingReturnType(funcExpr);
    const autofix = this.autofixer?.fixFunctionExpression(
      funcExpr, newRetTypeNode, ts.getModifiers(funcExpr), isGenerator, hasUnfixableReturnType
    );
    this.incrementCounters(funcExpr, FaultID.FunctionExpression, autofix);
    if (isGenerator) {
      this.incrementCounters(funcExpr, FaultID.GeneratorFunction);
    }
    if (!hasPredecessor(funcExpr, TypeScriptLinter.isClassLikeOrIface)) {
      this.reportThisKeywordsInScope(funcExpr.body);
    }
    if (hasUnfixableReturnType) {
      this.incrementCounters(funcExpr, FaultID.LimitedReturnTypeInference);
    }
  }

  private handleArrowFunction(node: ts.Node): void {
    const arrowFunc = node as ts.ArrowFunction;
    if (!hasPredecessor(arrowFunc, TypeScriptLinter.isClassLikeOrIface)) {
      this.reportThisKeywordsInScope(arrowFunc.body);
    }
    const contextType = this.tsTypeChecker.getContextualType(arrowFunc);
    if (!(contextType && this.tsUtils.isLibraryType(contextType))) {
      if (!arrowFunc.type) {
        this.handleMissingReturnType(arrowFunc);
      }
    }
  }

  private handleFunctionDeclaration(node: ts.Node): void {
    // early exit via exception if cancellation was requested
    this.cancellationToken?.throwIfCancellationRequested();

    const tsFunctionDeclaration = node as ts.FunctionDeclaration;
    if (!tsFunctionDeclaration.type) {
      this.handleMissingReturnType(tsFunctionDeclaration);
    }
    if (tsFunctionDeclaration.name) {
      this.countDeclarationsWithDuplicateName(tsFunctionDeclaration.name, tsFunctionDeclaration);
    }
    if (tsFunctionDeclaration.body) {
      this.reportThisKeywordsInScope(tsFunctionDeclaration.body);
    }
    const funcDeclParent = tsFunctionDeclaration.parent;
    if (!ts.isSourceFile(funcDeclParent) && !ts.isModuleBlock(funcDeclParent)) {
      const autofix = this.autofixer?.fixNestedFunction(tsFunctionDeclaration);
      this.incrementCounters(tsFunctionDeclaration, FaultID.LocalFunction, autofix);
    }
    if (tsFunctionDeclaration.asteriskToken) {
      this.incrementCounters(node, FaultID.GeneratorFunction);
    }
  }

  private handleMissingReturnType(
    funcLikeDecl: ts.FunctionLikeDeclaration | ts.MethodSignature
  ): [boolean, ts.TypeNode | undefined] {
    if (funcLikeDecl.type) {
      return [false, funcLikeDecl.type];
    }

    // Note: Return type can't be inferred for function without body.
    const isSignature = ts.isMethodSignature(funcLikeDecl);
    if (isSignature || !funcLikeDecl.body) {
      // Ambient flag is not exposed, so we apply dirty hack to make it visible
      const isAmbientDeclaration = !!(funcLikeDecl.flags & (ts.NodeFlags as any).Ambient);
      if ((isSignature || isAmbientDeclaration) && !funcLikeDecl.type) {
        this.incrementCounters(funcLikeDecl, FaultID.LimitedReturnTypeInference);
      }
      return [false, undefined];
    }

    return this.tryAutofixMissingReturnType(funcLikeDecl);
  }

  private tryAutofixMissingReturnType(funcLikeDecl: ts.FunctionLikeDeclaration): [boolean, ts.TypeNode | undefined] {
    if (!funcLikeDecl.body) {
      return [false, undefined];
    }

    let autofix: Autofix[] | undefined;
    let newRetTypeNode: ts.TypeNode | undefined;
    const isFuncExpr = ts.isFunctionExpression(funcLikeDecl);

    /*
     * Currently, ArkTS can't infer return type of function, when expression
     * in the return statement is a call to a function or method whose return
     * value type is omitted. In that case, we attempt to prepare an autofix.
     */
    let hasLimitedRetTypeInference = this.hasLimitedTypeInferenceFromReturnExpr(funcLikeDecl.body);
    const tsSignature = this.tsTypeChecker.getSignatureFromDeclaration(funcLikeDecl);
    if (tsSignature) {
      const tsRetType = this.tsTypeChecker.getReturnTypeOfSignature(tsSignature);
      if (!tsRetType || TsUtils.isUnsupportedType(tsRetType)) {
        hasLimitedRetTypeInference = true;
      } else if (hasLimitedRetTypeInference) {
        newRetTypeNode = this.tsTypeChecker.typeToTypeNode(tsRetType, funcLikeDecl, ts.NodeBuilderFlags.None);
        if (this.autofixer !== undefined && newRetTypeNode && !isFuncExpr) {
          autofix = this.autofixer.fixMissingReturnType(funcLikeDecl, newRetTypeNode);
        }
      }
    }

    /*
     * Don't report here if in function expression context.
     * See handleFunctionExpression for details.
     */
    if (hasLimitedRetTypeInference && !isFuncExpr) {
      this.incrementCounters(funcLikeDecl, FaultID.LimitedReturnTypeInference, autofix);
    }

    return [hasLimitedRetTypeInference && !newRetTypeNode, newRetTypeNode];
  }

  private hasLimitedTypeInferenceFromReturnExpr(funBody: ts.ConciseBody): boolean {
    let hasLimitedTypeInference = false;
    const callback = (node: ts.Node): void => {
      if (hasLimitedTypeInference) {
        return;
      }
      if (
        ts.isReturnStatement(node) &&
        node.expression &&
        this.tsUtils.isCallToFunctionWithOmittedReturnType(TsUtils.unwrapParenthesized(node.expression))
      ) {
        hasLimitedTypeInference = true;
      }
    };
    // Don't traverse other nested function-like declarations.
    const stopCondition = (node: ts.Node): boolean => {
      return (
        ts.isFunctionDeclaration(node) ||
        ts.isFunctionExpression(node) ||
        ts.isMethodDeclaration(node) ||
        ts.isAccessor(node) ||
        ts.isArrowFunction(node)
      );
    };
    if (ts.isBlock(funBody)) {
      forEachNodeInSubtree(funBody, callback, stopCondition);
    } else {
      const tsExpr = TsUtils.unwrapParenthesized(funBody);
      hasLimitedTypeInference = this.tsUtils.isCallToFunctionWithOmittedReturnType(tsExpr);
    }
    return hasLimitedTypeInference;
  }

  private isValidTypeForUnaryArithmeticOperator(type: ts.Type): boolean {
    const typeFlags = type.getFlags();
    const numberLiteralFlags = ts.TypeFlags.BigIntLiteral | ts.TypeFlags.NumberLiteral;
    const numberLikeFlags = ts.TypeFlags.BigIntLike | ts.TypeFlags.NumberLike;
    const isNumberLike = !!(typeFlags & (numberLiteralFlags | numberLikeFlags));

    const isAllowedNumericType = this.tsUtils.isStdBigIntType(type) || this.tsUtils.isStdNumberType(type);

    return isNumberLike || isAllowedNumericType;
  }

  private handlePrefixUnaryExpression(node: ts.Node): void {
    const tsUnaryArithm = node as ts.PrefixUnaryExpression;
    const tsUnaryOp = tsUnaryArithm.operator;
    const tsUnaryOperand = tsUnaryArithm.operand;
    if (
      tsUnaryOp === ts.SyntaxKind.PlusToken ||
      tsUnaryOp === ts.SyntaxKind.MinusToken ||
      tsUnaryOp === ts.SyntaxKind.TildeToken
    ) {
      const tsOperatndType = this.tsTypeChecker.getTypeAtLocation(tsUnaryOperand);
      const isTilde = tsUnaryOp === ts.SyntaxKind.TildeToken;
      const isInvalidTilde =
        isTilde && ts.isNumericLiteral(tsUnaryOperand) && !this.tsUtils.isIntegerConstantValue(tsUnaryOperand);
      if (!this.isValidTypeForUnaryArithmeticOperator(tsOperatndType) || isInvalidTilde) {
        this.incrementCounters(node, FaultID.UnaryArithmNotNumber);
      }
    }
  }

  private handleBinaryExpression(node: ts.Node): void {
    const tsBinaryExpr = node as ts.BinaryExpression;
    const tsLhsExpr = tsBinaryExpr.left;
    const tsRhsExpr = tsBinaryExpr.right;
    if (isAssignmentOperator(tsBinaryExpr.operatorToken)) {
      this.processBinaryAssignment(node, tsLhsExpr, tsRhsExpr);
    }
    const leftOperandType = this.tsTypeChecker.getTypeAtLocation(tsLhsExpr);
    const rightOperandType = this.tsTypeChecker.getTypeAtLocation(tsRhsExpr);
    const typeNode = this.tsUtils.getVariableDeclarationTypeNode(tsLhsExpr);
    switch (tsBinaryExpr.operatorToken.kind) {
      // FaultID.BitOpWithWrongType - removed as rule #61
      case ts.SyntaxKind.CommaToken:
        this.processBinaryComma(tsBinaryExpr);
        break;
      case ts.SyntaxKind.InstanceOfKeyword:
        this.processBinaryInstanceOf(node, tsLhsExpr, leftOperandType);
        break;
      case ts.SyntaxKind.InKeyword:
        this.incrementCounters(tsBinaryExpr.operatorToken, FaultID.InOperator);
        break;
      case ts.SyntaxKind.EqualsToken:
        if (this.tsUtils.needToDeduceStructuralIdentity(leftOperandType, rightOperandType, tsRhsExpr)) {
          this.incrementCounters(tsBinaryExpr, FaultID.StructuralIdentity);
        }
        this.handleEsObjectAssignment(tsBinaryExpr, typeNode, tsRhsExpr);
        break;
      default:
    }
  }

  private processBinaryAssignment(node: ts.Node, tsLhsExpr: ts.Expression, tsRhsExpr: ts.Expression): void {
    if (ts.isObjectLiteralExpression(tsLhsExpr)) {
      this.incrementCounters(node, FaultID.DestructuringAssignment);
    } else if (ts.isArrayLiteralExpression(tsLhsExpr)) {
      // Array destructuring is allowed only for Arrays/Tuples and without spread operator.
      const rhsType = this.tsTypeChecker.getTypeAtLocation(tsRhsExpr);
      const isArrayOrTuple =
        this.tsUtils.isOrDerivedFrom(rhsType, this.tsUtils.isArray) ||
        this.tsUtils.isOrDerivedFrom(rhsType, TsUtils.isTuple);
      const hasNestedObjectDestructuring = TsUtils.hasNestedObjectDestructuring(tsLhsExpr);

      if (!TypeScriptLinter.useRelaxedRules || !isArrayOrTuple || hasNestedObjectDestructuring ||
        TsUtils.destructuringAssignmentHasSpreadOperator(tsLhsExpr)
      ) {
        this.incrementCounters(node, FaultID.DestructuringAssignment);
      }
    }

    if (ts.isPropertyAccessExpression(tsLhsExpr)) {
      const tsLhsSymbol = this.tsUtils.trueSymbolAtLocation(tsLhsExpr);
      const tsLhsBaseSymbol = this.tsUtils.trueSymbolAtLocation(tsLhsExpr.expression);
      if (tsLhsSymbol && tsLhsSymbol.flags & ts.SymbolFlags.Method) {
        this.incrementCounters(tsLhsExpr, FaultID.MethodReassignment);
      }
      if (
        TsUtils.isMethodAssignment(tsLhsSymbol) &&
        tsLhsBaseSymbol &&
        (tsLhsBaseSymbol.flags & ts.SymbolFlags.Function) !== 0
      ) {
        this.incrementCounters(tsLhsExpr, FaultID.PropertyDeclOnFunction);
      }
    }
  }

  private processBinaryComma(tsBinaryExpr: ts.BinaryExpression): void {
    // CommaOpertor is allowed in 'for' statement initalizer and incrementor
    let tsExprNode: ts.Node = tsBinaryExpr;
    let tsParentNode = tsExprNode.parent;
    while (tsParentNode && tsParentNode.kind === ts.SyntaxKind.BinaryExpression) {
      tsExprNode = tsParentNode;
      tsParentNode = tsExprNode.parent;
      if ((tsExprNode as ts.BinaryExpression).operatorToken.kind === ts.SyntaxKind.CommaToken) {
        // Need to return if one comma enclosed in expression with another comma to avoid multiple reports on one line
        return;
      }
    }
    if (tsParentNode && tsParentNode.kind === ts.SyntaxKind.ForStatement) {
      const tsForNode = tsParentNode as ts.ForStatement;
      if (tsExprNode === tsForNode.initializer || tsExprNode === tsForNode.incrementor) {
        return;
      }
    }
    if (tsParentNode && tsParentNode.kind === ts.SyntaxKind.ExpressionStatement) {
      const autofix = this.autofixer?.fixCommaOperator(tsExprNode);
      this.incrementCounters(tsExprNode, FaultID.CommaOperator, autofix);
      return;
    }

    this.incrementCounters(tsBinaryExpr as ts.Node, FaultID.CommaOperator);
  }

  private processBinaryInstanceOf(node: ts.Node, tsLhsExpr: ts.Expression, leftOperandType: ts.Type): void {
    const leftExpr = TsUtils.unwrapParenthesized(tsLhsExpr);
    const leftSymbol = this.tsUtils.trueSymbolAtLocation(leftExpr);

    /*
     * In STS, the left-hand side expression may be of any reference type, otherwise
     * a compile-time error occurs. In addition, the left operand in STS cannot be a type.
     */
    if (tsLhsExpr.kind === ts.SyntaxKind.ThisKeyword) {
      return;
    }

    if (TsUtils.isPrimitiveType(leftOperandType) || ts.isTypeNode(leftExpr) || TsUtils.isTypeSymbol(leftSymbol)) {
      this.incrementCounters(node, FaultID.InstanceofUnsupported);
    }
  }

  private handleVariableDeclarationList(node: ts.Node): void {
    const varDeclFlags = ts.getCombinedNodeFlags(node);
    if (!(varDeclFlags & (ts.NodeFlags.Let | ts.NodeFlags.Const))) {
      const autofix = this.autofixer?.fixVarDeclaration(node as ts.VariableDeclarationList);
      this.incrementCounters(node, FaultID.VarDeclaration, autofix);
    }
  }

  private handleVariableDeclaration(node: ts.Node): void {
    const tsVarDecl = node as ts.VariableDeclaration;
    if (ts.isVariableDeclarationList(tsVarDecl.parent) && ts.isVariableStatement(tsVarDecl.parent.parent)) {
      this.handleDeclarationDestructuring(tsVarDecl);
    }

    // Check variable declaration for duplicate name.
    this.checkVarDeclForDuplicateNames(tsVarDecl.name);

    if (tsVarDecl.type && tsVarDecl.initializer) {
      const tsVarInit = tsVarDecl.initializer;
      const tsVarType = this.tsTypeChecker.getTypeAtLocation(tsVarDecl.type);
      const tsInitType = this.tsTypeChecker.getTypeAtLocation(tsVarInit);
      if (this.tsUtils.needToDeduceStructuralIdentity(tsVarType, tsInitType, tsVarInit)) {
        this.incrementCounters(tsVarDecl, FaultID.StructuralIdentity);
      }
    }
    this.handleEsObjectDelaration(tsVarDecl);
    this.handleDeclarationInferredType(tsVarDecl);
    this.handleDefiniteAssignmentAssertion(tsVarDecl);
  }

  private handleDeclarationDestructuring(decl: ts.VariableDeclaration | ts.ParameterDeclaration): void {
    const faultId = ts.isVariableDeclaration(decl) ? FaultID.DestructuringDeclaration : FaultID.DestructuringParameter;
    if (ts.isObjectBindingPattern(decl.name)) {
      this.incrementCounters(decl, faultId);
    } else if (ts.isArrayBindingPattern(decl.name)) {
      // Array destructuring is allowed only for Arrays/Tuples and without spread operator.
      const rhsType = this.tsTypeChecker.getTypeAtLocation(decl.initializer ?? decl.name);
      const isArrayOrTuple = rhsType && (
        this.tsUtils.isOrDerivedFrom(rhsType, this.tsUtils.isArray) ||
          this.tsUtils.isOrDerivedFrom(rhsType, TsUtils.isTuple)
      );
      const hasNestedObjectDestructuring = TsUtils.hasNestedObjectDestructuring(decl.name);

      if (!TypeScriptLinter.useRelaxedRules || !isArrayOrTuple || hasNestedObjectDestructuring ||
        TsUtils.destructuringDeclarationHasSpreadOperator(decl.name)
      ) {
        this.incrementCounters(decl, faultId);
      }
    }
  }

  private checkVarDeclForDuplicateNames(tsBindingName: ts.BindingName): void {
    if (ts.isIdentifier(tsBindingName)) {
      // The syntax kind of the declaration is defined here by the parent of 'BindingName' node.
      this.countDeclarationsWithDuplicateName(tsBindingName, tsBindingName, tsBindingName.parent.kind);
      return;
    }
    for (const tsBindingElem of tsBindingName.elements) {
      if (ts.isOmittedExpression(tsBindingElem)) {
        continue;
      }

      this.checkVarDeclForDuplicateNames(tsBindingElem.name);
    }
  }

  private handleEsObjectDelaration(node: ts.VariableDeclaration): void {
    const isDeclaredESObject = !!node.type && TsUtils.isEsObjectType(node.type);
    const initalizerTypeNode = node.initializer && this.tsUtils.getVariableDeclarationTypeNode(node.initializer);
    const isInitializedWithESObject = !!initalizerTypeNode && TsUtils.isEsObjectType(initalizerTypeNode);
    const isLocal = TsUtils.isInsideBlock(node);
    if ((isDeclaredESObject || isInitializedWithESObject) && !isLocal) {
      this.incrementCounters(node, FaultID.EsObjectType);
      return;
    }

    if (node.initializer) {
      this.handleEsObjectAssignment(node, node.type, node.initializer);
    }
  }

  private handleEsObjectAssignment(node: ts.Node, nodeDeclType: ts.TypeNode | undefined, initializer: ts.Node): void {
    const isTypeAnnotated = !!nodeDeclType;
    const isDeclaredESObject = isTypeAnnotated && TsUtils.isEsObjectType(nodeDeclType);
    const initalizerTypeNode = this.tsUtils.getVariableDeclarationTypeNode(initializer);
    const isInitializedWithESObject = !!initalizerTypeNode && TsUtils.isEsObjectType(initalizerTypeNode);
    if (isTypeAnnotated && !isDeclaredESObject && isInitializedWithESObject) {
      this.incrementCounters(node, FaultID.EsObjectType);
      return;
    }

    if (isDeclaredESObject && !this.tsUtils.isValueAssignableToESObject(initializer)) {
      this.incrementCounters(node, FaultID.EsObjectType);
    }
  }

  private handleCatchClause(node: ts.Node): void {
    const tsCatch = node as ts.CatchClause;

    /*
     * In TS catch clause doesn't permit specification of the exception varible type except 'any' or 'unknown'.
     * It is not compatible with STS 'catch' where the exception variable has to be of type
     * Error or derived from it.
     * So each 'catch' which has explicit type for the exception object goes to problems.
     */
    if (tsCatch.variableDeclaration?.type) {
      const autofix = this.autofixer?.dropTypeOnVarDecl(tsCatch.variableDeclaration);
      this.incrementCounters(node, FaultID.CatchWithUnsupportedType, autofix);
    }
  }

  private handleClassDeclaration(node: ts.Node): void {
    // early exit via exception if cancellation was requested
    this.cancellationToken?.throwIfCancellationRequested();

    const tsClassDecl = node as ts.ClassDeclaration;
    if (tsClassDecl.name) {
      this.countDeclarationsWithDuplicateName(tsClassDecl.name, tsClassDecl);
    }
    this.countClassMembersWithDuplicateName(tsClassDecl);

    const isSendableClass = TsUtils.hasSendableDecorator(tsClassDecl);
    if (isSendableClass) {
      TsUtils.getNonSendableDecorators(tsClassDecl)?.forEach((decorator) => {
        this.incrementCounters(decorator, FaultID.SendableClassDecorator);
      });
      tsClassDecl.typeParameters?.forEach((typeParamDecl) => {
        this.checkSendableTypeParameter(typeParamDecl);
      });
    }

    if (tsClassDecl.heritageClauses) {
      for (const hClause of tsClassDecl.heritageClauses) {
        if (!hClause) {
          continue;
        }
        this.checkClassDeclarationHeritageClause(hClause, isSendableClass);
      }
    }

    // Check captured variables for sendable class
    if (isSendableClass) {
      tsClassDecl.members.forEach((classMember) => {
        this.scanCapturedVarsInSendableScope(classMember, tsClassDecl);
      });
    }

    this.processClassStaticBlocks(tsClassDecl);
  }

  private checkClassDeclarationHeritageClause(hClause: ts.HeritageClause, isSendableClass: boolean): void {
    for (const tsTypeExpr of hClause.types) {

      /*
       * Always resolve type from 'tsTypeExpr' node, not from 'tsTypeExpr.expression' node,
       * as for the latter, type checker will return incorrect type result for classes in
       * 'extends' clause. Additionally, reduce reference, as mostly type checker returns
       * the TypeReference type objects for classes and interfaces.
       */
      const tsExprType = TsUtils.reduceReference(this.tsTypeChecker.getTypeAtLocation(tsTypeExpr));
      const isSendableBaseType = this.tsUtils.isSendableClassOrInterface(tsExprType);
      if (tsExprType.isClass() && hClause.token === ts.SyntaxKind.ImplementsKeyword) {
        this.incrementCounters(tsTypeExpr, FaultID.ImplementsClass);
      }
      if (!isSendableClass) {
        // Non-Sendable class can not implements sendable interface / extends sendable class
        if (isSendableBaseType) {
          this.incrementCounters(tsTypeExpr, FaultID.SendableClassInheritance);
        }
        continue;
      }

      /*
       * Sendable class can implements any interface / extends only sendable class
       * Sendable class can not extends sendable class variable(local / import)
       */
      if (hClause.token === ts.SyntaxKind.ExtendsKeyword) {
        if (!isSendableBaseType) {
          this.incrementCounters(tsTypeExpr, FaultID.SendableClassInheritance);
          continue;
        }
        if (!this.isValidSendableClassExtends(tsTypeExpr)) {
          this.incrementCounters(tsTypeExpr, FaultID.SendableClassInheritance);
        }
      }
    }
  }

  private isValidSendableClassExtends(tsTypeExpr: ts.ExpressionWithTypeArguments): boolean {
    const expr = tsTypeExpr.expression;
    const sym = this.tsTypeChecker.getSymbolAtLocation(expr);
    if (sym && (sym.flags & ts.SymbolFlags.Class) === 0) {
      // handle non-class situation(local / import)
      if ((sym.flags & ts.SymbolFlags.Alias) !== 0) {

        /*
         * Sendable class can not extends imported sendable class variable
         * Sendable class can extends imported sendable class
         */
        const realSym = this.tsTypeChecker.getAliasedSymbol(sym);
        if (realSym && (realSym.flags & ts.SymbolFlags.Class) === 0) {
          return false;
        }
        return true;
      }
      return false;
    }
    return true;
  }

  private checkSendableTypeParameter(typeParamDecl: ts.TypeParameterDeclaration): void {
    const defaultTypeNode = typeParamDecl.default;
    if (defaultTypeNode) {
      if (!this.tsUtils.isSendableTypeNode(defaultTypeNode)) {
        this.incrementCounters(defaultTypeNode, FaultID.SendableGenericTypes);
      }
    }
  }

  private processClassStaticBlocks(classDecl: ts.ClassDeclaration): void {
    let staticBlocksCntr = 0;
    const staticBlockNodes: ts.Node[] = [];
    for (const element of classDecl.members) {
      if (ts.isClassStaticBlockDeclaration(element)) {
        staticBlockNodes[staticBlocksCntr] = element;
        staticBlocksCntr++;
      }
    }
    if (staticBlocksCntr > 1) {
      const autofix = this.autofixer?.fixMultipleStaticBlocks(staticBlockNodes);
      // autofixes for all additional static blocks are the same
      for (let i = 1; i < staticBlocksCntr; i++) {
        this.incrementCounters(staticBlockNodes[i], FaultID.MultipleStaticBlocks, autofix);
      }
    }
  }

  private handleModuleDeclaration(node: ts.Node): void {
    // early exit via exception if cancellation was requested
    this.cancellationToken?.throwIfCancellationRequested();

    const tsModuleDecl = node as ts.ModuleDeclaration;

    this.countDeclarationsWithDuplicateName(tsModuleDecl.name, tsModuleDecl);

    const tsModuleBody = tsModuleDecl.body;
    const tsModifiers = ts.getModifiers(tsModuleDecl);
    if (tsModuleBody) {
      if (ts.isModuleBlock(tsModuleBody)) {
        this.handleModuleBlock(tsModuleBody);
      }
    }

    if (
      !(tsModuleDecl.flags & ts.NodeFlags.Namespace) &&
      TsUtils.hasModifier(tsModifiers, ts.SyntaxKind.DeclareKeyword)
    ) {
      this.incrementCounters(tsModuleDecl, FaultID.ShorthandAmbientModuleDecl);
    }

    if (ts.isStringLiteral(tsModuleDecl.name) && tsModuleDecl.name.text.includes('*')) {
      this.incrementCounters(tsModuleDecl, FaultID.WildcardsInModuleName);
    }
  }

  private handleModuleBlock(moduleBlock: ts.ModuleBlock): void {
    for (const tsModuleStmt of moduleBlock.statements) {
      switch (tsModuleStmt.kind) {
        case ts.SyntaxKind.VariableStatement:
        case ts.SyntaxKind.FunctionDeclaration:
        case ts.SyntaxKind.ClassDeclaration:
        case ts.SyntaxKind.InterfaceDeclaration:
        case ts.SyntaxKind.TypeAliasDeclaration:
        case ts.SyntaxKind.EnumDeclaration:
        case ts.SyntaxKind.ExportDeclaration:
          break;

        /*
         * Nested namespace declarations are prohibited
         * but there is no cookbook recipe for it!
         */
        case ts.SyntaxKind.ModuleDeclaration:
          break;
        default:
          this.incrementCounters(tsModuleStmt, FaultID.NonDeclarationInNamespace);
          break;
      }
    }
  }

  private handleTypeAliasDeclaration(node: ts.Node): void {
    const tsTypeAlias = node as ts.TypeAliasDeclaration;
    this.countDeclarationsWithDuplicateName(tsTypeAlias.name, tsTypeAlias);
  }

  private handleImportClause(node: ts.Node): void {
    const tsImportClause = node as ts.ImportClause;
    if (tsImportClause.name) {
      this.countDeclarationsWithDuplicateName(tsImportClause.name, tsImportClause);
    }
  }

  private handleImportSpecifier(node: ts.Node): void {
    const importSpec = node as ts.ImportSpecifier;
    this.countDeclarationsWithDuplicateName(importSpec.name, importSpec);
  }

  private handleNamespaceImport(node: ts.Node): void {
    const tsNamespaceImport = node as ts.NamespaceImport;
    this.countDeclarationsWithDuplicateName(tsNamespaceImport.name, tsNamespaceImport);
  }

  private handleTypeAssertionExpression(node: ts.Node): void {
    const tsTypeAssertion = node as ts.TypeAssertion;
    if (tsTypeAssertion.type.getText() === 'const') {
      this.incrementCounters(tsTypeAssertion, FaultID.ConstAssertion);
    } else {
      const autofix = this.autofixer?.fixTypeAssertion(tsTypeAssertion);
      this.incrementCounters(node, FaultID.TypeAssertion, autofix);
    }
  }

  private handleMethodDeclaration(node: ts.Node): void {
    const tsMethodDecl = node as ts.MethodDeclaration;
    TsUtils.getDecoratorsIfInSendableClass(tsMethodDecl)?.forEach((decorator) => {
      this.incrementCounters(decorator, FaultID.SendableClassDecorator);
    });
    let isStatic = false;
    if (tsMethodDecl.modifiers) {
      for (const mod of tsMethodDecl.modifiers) {
        if (mod.kind === ts.SyntaxKind.StaticKeyword) {
          isStatic = true;
          break;
        }
      }
    }
    if (tsMethodDecl.body && isStatic) {
      this.reportThisKeywordsInScope(tsMethodDecl.body);
    }
    if (!tsMethodDecl.type) {
      this.handleMissingReturnType(tsMethodDecl);
    }
    if (tsMethodDecl.asteriskToken) {
      this.incrementCounters(node, FaultID.GeneratorFunction);
    }
    this.filterOutDecoratorsDiagnostics(
      ts.getDecorators(tsMethodDecl),
      NON_RETURN_FUNCTION_DECORATORS,
      { begin: tsMethodDecl.parameters.end, end: tsMethodDecl.body?.getStart() ?? tsMethodDecl.parameters.end },
      FUNCTION_HAS_NO_RETURN_ERROR_CODE
    );
  }

  private handleMethodSignature(node: ts.MethodSignature): void {
    const tsMethodSign = node;
    if (!tsMethodSign.type) {
      this.handleMissingReturnType(tsMethodSign);
    }
  }

  private handleClassStaticBlockDeclaration(node: ts.Node): void {
    const classStaticBlockDecl = node as ts.ClassStaticBlockDeclaration;
    if (!ts.isClassDeclaration(classStaticBlockDecl.parent)) {
      return;
    }
    this.reportThisKeywordsInScope(classStaticBlockDecl.body);
  }

  private handleIdentifier(node: ts.Node): void {
    const tsIdentifier = node as ts.Identifier;
    const tsIdentSym = this.tsUtils.trueSymbolAtLocation(tsIdentifier);
    if (!tsIdentSym) {
      return;
    }
    if (
      (tsIdentSym.flags & ts.SymbolFlags.Module) !== 0 &&
      (tsIdentSym.flags & ts.SymbolFlags.Transient) !== 0 &&
      tsIdentifier.text === 'globalThis'
    ) {
      this.incrementCounters(node, FaultID.GlobalThis);
    } else {
      this.handleRestrictedValues(tsIdentifier, tsIdentSym);
    }
  }

  // hard-coded alternative to TypeScriptLinter.advancedClassChecks
  private isAllowedClassValueContext(tsIdentifier: ts.Identifier): boolean {
    let ctx: ts.Node = tsIdentifier;
    while (ts.isPropertyAccessExpression(ctx.parent) || ts.isQualifiedName(ctx.parent)) {
      ctx = ctx.parent;
    }
    if (ts.isPropertyAssignment(ctx.parent) && ts.isObjectLiteralExpression(ctx.parent.parent)) {
      ctx = ctx.parent.parent;
    }
    if (ts.isArrowFunction(ctx.parent) && ctx.parent.body === ctx) {
      ctx = ctx.parent;
    }

    if (ts.isCallExpression(ctx.parent) || ts.isNewExpression(ctx.parent)) {
      const callee = ctx.parent.expression;
      const isAny = TsUtils.isAnyType(this.tsTypeChecker.getTypeAtLocation(callee));
      const isDynamic = isAny || this.tsUtils.hasLibraryType(callee);
      if (callee !== ctx && isDynamic) {
        return true;
      }
    }
    return false;
  }

  private handleRestrictedValues(tsIdentifier: ts.Identifier, tsIdentSym: ts.Symbol): void {
    const illegalValues =
      ts.SymbolFlags.ConstEnum |
      ts.SymbolFlags.RegularEnum |
      ts.SymbolFlags.ValueModule |
      (TypeScriptLinter.advancedClassChecks ? 0 : ts.SymbolFlags.Class);

    /*
     * If module name is duplicated by another declaration, this increases the possibility
     * of finding a lot of false positives. Thus, do not check further in that case.
     */
    if ((tsIdentSym.flags & ts.SymbolFlags.ValueModule) !== 0) {
      if (!!tsIdentSym && TsUtils.symbolHasDuplicateName(tsIdentSym, ts.SyntaxKind.ModuleDeclaration)) {
        return;
      }
    }

    if (
      (tsIdentSym.flags & illegalValues) === 0 ||
      isStruct(tsIdentSym) ||
      !identiferUseInValueContext(tsIdentifier, tsIdentSym)
    ) {
      return;
    }

    if ((tsIdentSym.flags & ts.SymbolFlags.Class) !== 0) {
      if (!TypeScriptLinter.advancedClassChecks && this.isAllowedClassValueContext(tsIdentifier)) {
        return;
      }
    }

    if (tsIdentSym.flags & ts.SymbolFlags.ValueModule) {
      this.incrementCounters(tsIdentifier, FaultID.NamespaceAsObject);
    } else {
      // missing EnumAsObject
      this.incrementCounters(tsIdentifier, FaultID.ClassAsObject);
    }
  }

  private isElementAcessAllowed(type: ts.Type, argType: ts.Type): boolean {
    if (type.isUnion()) {
      for (const t of type.types) {
        if (!this.isElementAcessAllowed(t, argType)) {
          return false;
        }
      }
      return true;
    }

    const typeNode = this.tsTypeChecker.typeToTypeNode(type, undefined, ts.NodeBuilderFlags.None);

    if (TsUtils.isArkTSCollectionsArrayLikeType(type)) {
      return TsUtils.isNumberLikeType(argType);
    }

    return (
      this.tsUtils.isLibraryType(type) ||
      TsUtils.isAnyType(type) ||
      this.tsUtils.isOrDerivedFrom(type, this.tsUtils.isArray) ||
      this.tsUtils.isOrDerivedFrom(type, TsUtils.isTuple) ||
      this.tsUtils.isOrDerivedFrom(type, this.tsUtils.isStdRecordType) ||
      this.tsUtils.isOrDerivedFrom(type, this.tsUtils.isStringType) ||
      this.tsUtils.isOrDerivedFrom(type, this.tsUtils.isStdMapType) ||
      TsUtils.isIntrinsicObjectType(type) ||
      TsUtils.isEnumType(type) ||
      // we allow EsObject here beacuse it is reported later using FaultId.EsObjectType
      TsUtils.isEsObjectType(typeNode)
    );
  }

  private handleElementAccessExpression(node: ts.Node): void {
    const tsElementAccessExpr = node as ts.ElementAccessExpression;
    const tsElementAccessExprSymbol = this.tsUtils.trueSymbolAtLocation(tsElementAccessExpr.expression);
    const tsElemAccessBaseExprType = TsUtils.getNonNullableType(
      this.tsUtils.getTypeOrTypeConstraintAtLocation(tsElementAccessExpr.expression)
    );
    const tsElemAccessArgType = this.tsTypeChecker.getTypeAtLocation(tsElementAccessExpr.argumentExpression);

    if (
      // unnamed types do not have symbol, so need to check that explicitly
      !this.tsUtils.isLibrarySymbol(tsElementAccessExprSymbol) &&
      !ts.isArrayLiteralExpression(tsElementAccessExpr.expression) &&
      !this.isElementAcessAllowed(tsElemAccessBaseExprType, tsElemAccessArgType)
    ) {
      const autofix = this.autofixer?.fixPropertyAccessByIndex(tsElementAccessExpr);
      this.incrementCounters(node, FaultID.PropertyAccessByIndex, autofix);
    }

    if (this.tsUtils.hasEsObjectType(tsElementAccessExpr.expression)) {
      this.incrementCounters(node, FaultID.EsObjectType);
    }
  }

  private handleEnumMember(node: ts.Node): void {
    const tsEnumMember = node as ts.EnumMember;
    const tsEnumMemberType = this.tsTypeChecker.getTypeAtLocation(tsEnumMember);
    const constVal = this.tsTypeChecker.getConstantValue(tsEnumMember);
    if (tsEnumMember.initializer && !this.tsUtils.isValidEnumMemberInit(tsEnumMember.initializer)) {
      this.incrementCounters(node, FaultID.EnumMemberNonConstInit);
    }
    // check for type - all members should be of same type
    const enumDecl = tsEnumMember.parent;
    const firstEnumMember = enumDecl.members[0];
    const firstEnumMemberType = this.tsTypeChecker.getTypeAtLocation(firstEnumMember);
    const firstElewmVal = this.tsTypeChecker.getConstantValue(firstEnumMember);

    /*
     * each string enum member has its own type
     * so check that value type is string
     */
    if (
      constVal !== undefined &&
      typeof constVal === 'string' &&
      firstElewmVal !== undefined &&
      typeof firstElewmVal === 'string'
    ) {
      return;
    }
    if (
      constVal !== undefined &&
      typeof constVal === 'number' &&
      firstElewmVal !== undefined &&
      typeof firstElewmVal === 'number'
    ) {
      return;
    }
    if (firstEnumMemberType !== tsEnumMemberType) {
      this.incrementCounters(node, FaultID.EnumMemberNonConstInit);
    }
  }

  private handleExportAssignment(node: ts.Node): void {
    const exportAssignment = node as ts.ExportAssignment;
    if (exportAssignment.isExportEquals) {
      this.incrementCounters(node, FaultID.ExportAssignment);
    }

    if (!TypeScriptLinter.inSharedModule(node)) {
      return;
    }

    if (!this.tsUtils.isShareableEntity(exportAssignment.expression)) {
      this.incrementCounters(exportAssignment.expression, FaultID.SharedModuleExports);
    }
  }

  private handleCallExpression(node: ts.Node): void {
    const tsCallExpr = node as ts.CallExpression;

    const calleeSym = this.tsUtils.trueSymbolAtLocation(tsCallExpr.expression);
    const callSignature = this.tsTypeChecker.getResolvedSignature(tsCallExpr);

    this.handleImportCall(tsCallExpr);
    this.handleRequireCall(tsCallExpr);
    if (calleeSym !== undefined) {
      this.handleStdlibAPICall(tsCallExpr, calleeSym);
      this.handleFunctionApplyBindPropCall(tsCallExpr, calleeSym);
      if (TsUtils.symbolHasEsObjectType(calleeSym)) {
        this.incrementCounters(tsCallExpr, FaultID.EsObjectType);
      }
    }
    if (callSignature !== undefined && !this.tsUtils.isLibrarySymbol(calleeSym)) {
      this.handleGenericCallWithNoTypeArgs(tsCallExpr, callSignature);
      this.handleStructIdentAndUndefinedInArgs(tsCallExpr, callSignature);
    }
    this.handleLibraryTypeCall(tsCallExpr);

    if (
      ts.isPropertyAccessExpression(tsCallExpr.expression) &&
      this.tsUtils.hasEsObjectType(tsCallExpr.expression.expression)
    ) {
      this.incrementCounters(node, FaultID.EsObjectType);
    }
  }

  private handleEtsComponentExpression(node: ts.Node): void {
    // for all the checks we make EtsComponentExpression is compatible with the CallExpression
    const etsComponentExpression = node as ts.CallExpression;
    this.handleLibraryTypeCall(etsComponentExpression);
  }

  private handleImportCall(tsCallExpr: ts.CallExpression): void {
    if (tsCallExpr.expression.kind === ts.SyntaxKind.ImportKeyword) {
      // relax rule#133 "arkts-no-runtime-import"
      const tsArgs = tsCallExpr.arguments;
      if (tsArgs.length > 1 && ts.isObjectLiteralExpression(tsArgs[1])) {
        for (const tsProp of tsArgs[1].properties) {
          if (
            (ts.isPropertyAssignment(tsProp) || ts.isShorthandPropertyAssignment(tsProp)) &&
            tsProp.name.getText() === 'assert'
          ) {
            this.incrementCounters(tsProp, FaultID.ImportAssertion);
            break;
          }
        }
      }
    }
  }

  private handleRequireCall(tsCallExpr: ts.CallExpression): void {
    if (
      ts.isIdentifier(tsCallExpr.expression) &&
      tsCallExpr.expression.text === 'require' &&
      ts.isVariableDeclaration(tsCallExpr.parent)
    ) {
      const tsType = this.tsTypeChecker.getTypeAtLocation(tsCallExpr.expression);
      if (TsUtils.isInterfaceType(tsType) && tsType.symbol.name === 'NodeRequire') {
        this.incrementCounters(tsCallExpr.parent, FaultID.ImportAssignment);
      }
    }
  }

  private handleGenericCallWithNoTypeArgs(
    callLikeExpr: ts.CallExpression | ts.NewExpression,
    callSignature: ts.Signature
  ): void {

    /*
     * Note: The PR!716 has led to a significant performance degradation.
     * Since initial problem was fixed in a more general way, this change
     * became redundant. Therefore, it was reverted. See #13721 comments
     * for a detailed analysis.
     */
    const tsSyntaxKind = ts.isNewExpression(callLikeExpr) ?
      ts.SyntaxKind.Constructor :
      ts.SyntaxKind.FunctionDeclaration;
    const signFlags = ts.NodeBuilderFlags.WriteTypeArgumentsOfSignature | ts.NodeBuilderFlags.IgnoreErrors;

    const signDecl = this.tsTypeChecker.signatureToSignatureDeclaration(
      callSignature,
      tsSyntaxKind,
      undefined,
      signFlags
    );
    if (!signDecl?.typeArguments) {
      return;
    }
    const resolvedTypeArgs = signDecl.typeArguments;
    const startTypeArg = callLikeExpr.typeArguments?.length ?? 0;
    for (let i = startTypeArg; i < resolvedTypeArgs.length; ++i) {
      const typeNode = resolvedTypeArgs[i];

      /*
       * if compiler infers 'unknown' type there are 2 possible cases:
       *   1. Compiler unable to infer type from arguments and use 'unknown'
       *   2. Compiler infer 'unknown' from arguments
       * We report error in both cases. It is ok because we cannot use 'unknown'
       * in ArkTS and already have separate check for it.
       */
      if (typeNode.kind === ts.SyntaxKind.UnknownKeyword) {
        this.incrementCounters(callLikeExpr, FaultID.GenericCallNoTypeArgs);
        break;
      }
    }
  }

  private static readonly listFunctionApplyCallApis = [
    'Function.apply',
    'Function.call',
    'CallableFunction.apply',
    'CallableFunction.call'
  ];

  private static readonly listFunctionBindApis = ['Function.bind', 'CallableFunction.bind'];

  private handleFunctionApplyBindPropCall(tsCallExpr: ts.CallExpression, calleeSym: ts.Symbol): void {
    const exprName = this.tsTypeChecker.getFullyQualifiedName(calleeSym);
    if (TypeScriptLinter.listFunctionApplyCallApis.includes(exprName)) {
      this.incrementCounters(tsCallExpr, FaultID.FunctionApplyCall);
    }
    if (TypeScriptLinter.listFunctionBindApis.includes(exprName)) {
      this.incrementCounters(tsCallExpr, FaultID.FunctionBind);
    }
  }

  private handleStructIdentAndUndefinedInArgs(
    tsCallOrNewExpr: ts.CallExpression | ts.NewExpression,
    callSignature: ts.Signature
  ): void {
    if (!tsCallOrNewExpr.arguments) {
      return;
    }
    for (let argIndex = 0; argIndex < tsCallOrNewExpr.arguments.length; ++argIndex) {
      const tsArg = tsCallOrNewExpr.arguments[argIndex];
      const tsArgType = this.tsTypeChecker.getTypeAtLocation(tsArg);
      if (!tsArgType) {
        continue;
      }
      const paramIndex = argIndex < callSignature.parameters.length ? argIndex : callSignature.parameters.length - 1;
      const tsParamSym = callSignature.parameters[paramIndex];
      if (!tsParamSym) {
        continue;
      }
      const tsParamDecl = tsParamSym.valueDeclaration;
      if (tsParamDecl && ts.isParameter(tsParamDecl)) {
        let tsParamType = this.tsTypeChecker.getTypeOfSymbolAtLocation(tsParamSym, tsParamDecl);
        if (tsParamDecl.dotDotDotToken && TsUtils.isGenericArrayType(tsParamType) && tsParamType.typeArguments) {
          tsParamType = tsParamType.typeArguments[0];
        }
        if (!tsParamType) {
          continue;
        }
        if (this.tsUtils.needToDeduceStructuralIdentity(tsParamType, tsArgType, tsArg)) {
          this.incrementCounters(tsArg, FaultID.StructuralIdentity);
        }
      }
    }
  }

  private static readonly LimitedApis = new Map<string, { arr: Array<string> | null; fault: FaultID }>([
    ['global', { arr: LIMITED_STD_GLOBAL_FUNC, fault: FaultID.LimitedStdLibApi }],
    ['Object', { arr: LIMITED_STD_OBJECT_API, fault: FaultID.LimitedStdLibApi }],
    ['ObjectConstructor', { arr: LIMITED_STD_OBJECT_API, fault: FaultID.LimitedStdLibApi }],
    ['Reflect', { arr: LIMITED_STD_REFLECT_API, fault: FaultID.LimitedStdLibApi }],
    ['ProxyHandler', { arr: LIMITED_STD_PROXYHANDLER_API, fault: FaultID.LimitedStdLibApi }],
    ['Symbol', { arr: null, fault: FaultID.SymbolType }],
    ['SymbolConstructor', { arr: null, fault: FaultID.SymbolType }]
  ]);

  private handleStdlibAPICall(callExpr: ts.CallExpression, calleeSym: ts.Symbol): void {
    const name = calleeSym.getName();
    const parName = this.tsUtils.getParentSymbolName(calleeSym);
    if (parName === undefined) {
      if (LIMITED_STD_GLOBAL_FUNC.includes(name)) {
        this.incrementCounters(callExpr, FaultID.LimitedStdLibApi);
        return;
      }
      const escapedName = calleeSym.escapedName;
      if (escapedName === 'Symbol' || escapedName === 'SymbolConstructor') {
        this.incrementCounters(callExpr, FaultID.SymbolType);
      }
      return;
    }
    const lookup = TypeScriptLinter.LimitedApis.get(parName);
    if (lookup !== undefined && (lookup.arr === null || lookup.arr.includes(name)) &&
      (!TypeScriptLinter.useRelaxedRules ||
       !this.supportedStdCallApiChecker.isSupportedStdCallAPI(callExpr, parName, name))
    ) {
      this.incrementCounters(callExpr, lookup.fault);
    }
  }

  private static findNonFilteringRangesFunctionCalls(callExpr: ts.CallExpression): { begin: number; end: number }[] {
    const args = callExpr.arguments;
    const result: { begin: number; end: number }[] = [];
    for (const arg of args) {
      if (ts.isArrowFunction(arg)) {
        const arrowFuncExpr = arg;
        result.push({ begin: arrowFuncExpr.body.pos, end: arrowFuncExpr.body.end });
      } else if (ts.isCallExpression(arg)) {
        result.push({ begin: arg.arguments.pos, end: arg.arguments.end });
      }
      // there may be other cases
    }
    return result;
  }

  private handleLibraryTypeCall(callExpr: ts.CallExpression): void {
    const calleeType = this.tsTypeChecker.getTypeAtLocation(callExpr.expression);
    const inLibCall = this.tsUtils.isLibraryType(calleeType);
    const diagnosticMessages: Array<ts.DiagnosticMessageChain> = [];

    this.libraryTypeCallDiagnosticChecker.configure(inLibCall, diagnosticMessages);

    const nonFilteringRanges = TypeScriptLinter.findNonFilteringRangesFunctionCalls(callExpr);
    const rangesToFilter: { begin: number; end: number }[] = [];
    if (nonFilteringRanges.length !== 0) {
      const rangesSize = nonFilteringRanges.length;
      rangesToFilter.push({ begin: callExpr.arguments.pos, end: nonFilteringRanges[0].begin });
      rangesToFilter.push({ begin: nonFilteringRanges[rangesSize - 1].end, end: callExpr.arguments.end });
      for (let i = 0; i < rangesSize - 1; i++) {
        rangesToFilter.push({ begin: nonFilteringRanges[i].end, end: nonFilteringRanges[i + 1].begin });
      }
    } else {
      rangesToFilter.push({ begin: callExpr.arguments.pos, end: callExpr.arguments.end });
    }

    this.filterStrictDiagnostics(
      {
        [ARGUMENT_OF_TYPE_0_IS_NOT_ASSIGNABLE_TO_PARAMETER_OF_TYPE_1_ERROR_CODE]: (pos: number) => {
          return TypeScriptLinter.checkInRange(rangesToFilter, pos);
        },
        [NO_OVERLOAD_MATCHES_THIS_CALL_ERROR_CODE]: (pos: number) => {
          return TypeScriptLinter.checkInRange(rangesToFilter, pos);
        },
        [TYPE_0_IS_NOT_ASSIGNABLE_TO_TYPE_1_ERROR_CODE]: (pos: number) => {
          return TypeScriptLinter.checkInRange(rangesToFilter, pos);
        }
      },
      this.libraryTypeCallDiagnosticChecker
    );

    for (const msgChain of diagnosticMessages) {
      TypeScriptLinter.filteredDiagnosticMessages.add(msgChain);
    }
  }

  private handleNewExpression(node: ts.Node): void {
    const tsNewExpr = node as ts.NewExpression;

    if (TypeScriptLinter.advancedClassChecks) {
      const calleeExpr = tsNewExpr.expression;
      const calleeType = this.tsTypeChecker.getTypeAtLocation(calleeExpr);
      if (
        !this.tsUtils.isClassTypeExrepssion(calleeExpr) &&
        !isStdLibraryType(calleeType) &&
        !this.tsUtils.isLibraryType(calleeType) &&
        !this.tsUtils.hasEsObjectType(calleeExpr)
      ) {
        // missing exact rule
        this.incrementCounters(calleeExpr, FaultID.ClassAsObject);
      }
    }
    const callSignature = this.tsTypeChecker.getResolvedSignature(tsNewExpr);
    if (callSignature !== undefined) {
      this.handleStructIdentAndUndefinedInArgs(tsNewExpr, callSignature);
      this.handleGenericCallWithNoTypeArgs(tsNewExpr, callSignature);
    }
    this.handleSendableGenericTypes(tsNewExpr);
  }

  private handleSendableGenericTypes(node: ts.NewExpression): void {
    const type = this.tsTypeChecker.getTypeAtLocation(node);
    if (!this.tsUtils.isSendableClassOrInterface(type)) {
      return;
    }

    const typeArgs = node.typeArguments;
    if (!typeArgs || typeArgs.length === 0) {
      return;
    }

    for (const arg of typeArgs) {
      if (!this.tsUtils.isSendableTypeNode(arg)) {
        this.incrementCounters(arg, FaultID.SendableGenericTypes);
      }
    }
  }

  private handleAsExpression(node: ts.Node): void {
    const tsAsExpr = node as ts.AsExpression;
    if (tsAsExpr.type.getText() === 'const') {
      this.incrementCounters(node, FaultID.ConstAssertion);
    }
    const targetType = this.tsTypeChecker.getTypeAtLocation(tsAsExpr.type).getNonNullableType();
    const exprType = this.tsTypeChecker.getTypeAtLocation(tsAsExpr.expression).getNonNullableType();
    // check for rule#65:   'number as Number' and 'boolean as Boolean' are disabled
    if (
      TsUtils.isNumberLikeType(exprType) && this.tsUtils.isStdNumberType(targetType) ||
      TsUtils.isBooleanLikeType(exprType) && this.tsUtils.isStdBooleanType(targetType)
    ) {
      this.incrementCounters(node, FaultID.TypeAssertion);
    }
    if (
      !this.tsUtils.isSendableClassOrInterface(exprType) &&
      !this.tsUtils.isObject(exprType) &&
      !TsUtils.isAnyType(exprType) &&
      this.tsUtils.isSendableClassOrInterface(targetType)
    ) {
      this.incrementCounters(tsAsExpr, FaultID.SendableAsExpr);
    }
  }

  private handleTypeReference(node: ts.Node): void {
    const typeRef = node as ts.TypeReferenceNode;

    const isESObject = TsUtils.isEsObjectType(typeRef);
    const isPossiblyValidContext = TsUtils.isEsObjectPossiblyAllowed(typeRef);
    if (isESObject && !isPossiblyValidContext) {
      this.incrementCounters(node, FaultID.EsObjectType);
      return;
    }

    const typeName = this.tsUtils.entityNameToString(typeRef.typeName);
    const isStdUtilityType = LIMITED_STANDARD_UTILITY_TYPES.includes(typeName);
    if (isStdUtilityType) {
      this.incrementCounters(node, FaultID.UtilityType);
      return;
    }

    // Using Partial<T> type is allowed only when its argument type is either Class or Interface.
    const isStdPartial = this.tsUtils.entityNameToString(typeRef.typeName) === 'Partial';
    const hasSingleTypeArgument = !!typeRef.typeArguments && typeRef.typeArguments.length === 1;
    const argType = hasSingleTypeArgument && this.tsTypeChecker.getTypeFromTypeNode(typeRef.typeArguments[0]);
    if (isStdPartial && argType && !argType.isClassOrInterface()) {
      this.incrementCounters(node, FaultID.UtilityType);
    }
  }

  private handleMetaProperty(node: ts.Node): void {
    const tsMetaProperty = node as ts.MetaProperty;
    if (tsMetaProperty.name.text === 'target') {
      this.incrementCounters(node, FaultID.NewTarget);
    }
  }

  private handleSpreadOp(node: ts.Node): void {

    /*
     * spread assignment is disabled
     * spread element is allowed only for arrays as rest parameter
     */
    if (ts.isSpreadElement(node)) {
      const spreadExprType = this.tsUtils.getTypeOrTypeConstraintAtLocation(node.expression);
      if (spreadExprType && this.tsUtils.isOrDerivedFrom(spreadExprType, this.tsUtils.isArray)) {
        return;
      }
    }
    this.incrementCounters(node, FaultID.SpreadOperator);
  }

  private handleConstructSignature(node: ts.Node): void {
    switch (node.parent.kind) {
      case ts.SyntaxKind.TypeLiteral:
        this.incrementCounters(node, FaultID.ConstructorType);
        break;
      case ts.SyntaxKind.InterfaceDeclaration:
        this.incrementCounters(node, FaultID.ConstructorIface);
        break;
      default:
    }
  }

  private handleExpressionWithTypeArguments(node: ts.Node): void {
    const tsTypeExpr = node as ts.ExpressionWithTypeArguments;
    const symbol = this.tsUtils.trueSymbolAtLocation(tsTypeExpr.expression);
    if (!!symbol && TsUtils.isEsObjectSymbol(symbol)) {
      this.incrementCounters(tsTypeExpr, FaultID.EsObjectType);
    }
  }

  private handleComputedPropertyName(node: ts.Node): void {
    const computedProperty = node as ts.ComputedPropertyName;
    if (this.isSendableInvalidCompPropName(computedProperty)) {
      this.incrementCounters(node, FaultID.SendableComputedPropName);
    } else if (!this.tsUtils.isValidComputedPropertyName(computedProperty, false)) {
      this.incrementCounters(node, FaultID.ComputedPropertyName);
    }
  }

  private isSendableInvalidCompPropName(compProp: ts.ComputedPropertyName): boolean {
    const declNode = compProp.parent?.parent;
    if (declNode && ts.isClassDeclaration(declNode) && TsUtils.hasSendableDecorator(declNode)) {
      return true;
    } else if (declNode && ts.isInterfaceDeclaration(declNode)) {
      const declNodeType = this.tsTypeChecker.getTypeAtLocation(declNode);
      if (this.tsUtils.isSendableClassOrInterface(declNodeType)) {
        return true;
      }
    }
    return false;
  }

  private handleGetAccessor(node: ts.GetAccessorDeclaration): void {
    TsUtils.getDecoratorsIfInSendableClass(node)?.forEach((decorator) => {
      this.incrementCounters(decorator, FaultID.SendableClassDecorator);
    });
  }

  private handleSetAccessor(node: ts.SetAccessorDeclaration): void {
    TsUtils.getDecoratorsIfInSendableClass(node)?.forEach((decorator) => {
      this.incrementCounters(decorator, FaultID.SendableClassDecorator);
    });
  }

  private handleDeclarationInferredType(
    decl: ts.VariableDeclaration | ts.PropertyDeclaration | ts.ParameterDeclaration
  ): void {
    // The type is explicitly specified, no need to check inferred type.
    if (decl.type) {
      return;
    }

    /*
     * issue 13161:
     * In TypeScript, the catch clause variable must be 'any' or 'unknown' type. Since
     * ArkTS doesn't support these types, the type for such variable is simply omitted,
     * and we don't report it as an error. See TypeScriptLinter.handleCatchClause()
     * for reference.
     */
    if (ts.isCatchClause(decl.parent)) {
      return;
    }
    // Destructuring declarations are not supported, do not process them.
    if (ts.isArrayBindingPattern(decl.name) || ts.isObjectBindingPattern(decl.name)) {
      return;
    }

    /*
     * issue 13987:
     * When variable have no type annotation and no initial value, and 'noImplicitAny'
     * option is enabled, compiler attempts to infer type from variable references:
     * see https://github.com/microsoft/TypeScript/pull/11263.
     * In this case, we still want to report the error, since ArkTS doesn't allow
     * to omit both type annotation and initializer.
     */
    if (
      (ts.isVariableDeclaration(decl) && ts.isVariableStatement(decl.parent.parent) ||
        ts.isPropertyDeclaration(decl)) && !decl.initializer
    ) {
      if (ts.isPropertyDeclaration(decl) &&
        TsUtils.skipPropertyInferredTypeCheck(decl, this.sourceFile, this.isEtsFileCb)
      ) {
        return;
      }

      this.incrementCounters(decl, FaultID.AnyType);
      return;
    }

    const type = this.tsTypeChecker.getTypeAtLocation(decl);
    if (type) {
      this.validateDeclInferredType(type, decl);
    }
  }

  private handleDefiniteAssignmentAssertion(decl: ts.VariableDeclaration | ts.PropertyDeclaration): void {
    if (decl.exclamationToken === undefined) {
      return;
    }

    if (decl.kind === ts.SyntaxKind.PropertyDeclaration) {
      const parentDecl = decl.parent;
      if (parentDecl.kind === ts.SyntaxKind.ClassDeclaration && TsUtils.hasSendableDecorator(parentDecl)) {
        this.incrementCounters(decl, FaultID.SendableDefiniteAssignment);
        return;
      }
    }
    this.incrementCounters(decl, FaultID.DefiniteAssignment);
  }

  private readonly validatedTypesSet = new Set<ts.Type>();

  private checkAnyOrUnknownChildNode(node: ts.Node): boolean {
    if (node.kind === ts.SyntaxKind.AnyKeyword || node.kind === ts.SyntaxKind.UnknownKeyword) {
      return true;
    }
    for (const child of node.getChildren()) {
      if (this.checkAnyOrUnknownChildNode(child)) {
        return true;
      }
    }
    return false;
  }

  private handleInferredObjectreference(
    type: ts.Type,
    decl: ts.VariableDeclaration | ts.PropertyDeclaration | ts.ParameterDeclaration
  ): void {
    const typeArgs = this.tsTypeChecker.getTypeArguments(type as ts.TypeReference);
    if (typeArgs) {
      const haveAnyOrUnknownNodes = this.checkAnyOrUnknownChildNode(decl);
      if (!haveAnyOrUnknownNodes) {
        for (const typeArg of typeArgs) {
          this.validateDeclInferredType(typeArg, decl);
        }
      }
    }
  }

  private validateDeclInferredType(
    type: ts.Type,
    decl: ts.VariableDeclaration | ts.PropertyDeclaration | ts.ParameterDeclaration
  ): void {
    if (type.aliasSymbol !== undefined) {
      return;
    }
    if (TsUtils.isObjectType(type) && !!(type.objectFlags & ts.ObjectFlags.Reference)) {
      this.handleInferredObjectreference(type, decl);
      return;
    }
    if (this.validatedTypesSet.has(type)) {
      return;
    }
    if (type.isUnion()) {
      this.validatedTypesSet.add(type);
      for (const unionElem of type.types) {
        this.validateDeclInferredType(unionElem, decl);
      }
    }
    if (TsUtils.isAnyType(type)) {
      this.incrementCounters(decl, FaultID.AnyType);
    } else if (TsUtils.isUnknownType(type)) {
      this.incrementCounters(decl, FaultID.UnknownType);
    }
  }

  private handleCommentDirectives(sourceFile: ts.SourceFile): void {

    /*
     * We use a dirty hack to retrieve list of parsed comment directives by accessing
     * internal properties of SourceFile node.
     */

    // Handle comment directive '@ts-nocheck'
    const pragmas = (sourceFile as any).pragmas;
    if (pragmas && pragmas instanceof Map) {
      const noCheckPragma = pragmas.get('ts-nocheck');
      if (noCheckPragma) {

        /*
         * The value is either a single entry or an array of entries.
         * Wrap up single entry with array to simplify processing.
         */
        const noCheckEntries: any[] = Array.isArray(noCheckPragma) ? noCheckPragma : [noCheckPragma];
        for (const entry of noCheckEntries) {
          this.processNoCheckEntry(entry);
        }
      }
    }

    // Handle comment directives '@ts-ignore' and '@ts-expect-error'
    const commentDirectives = (sourceFile as any).commentDirectives;
    if (commentDirectives && Array.isArray(commentDirectives)) {
      for (const directive of commentDirectives) {
        if (directive.range?.pos === undefined || directive.range?.end === undefined) {
          continue;
        }

        const range = directive.range as ts.TextRange;
        const kind: ts.SyntaxKind =
          sourceFile.text.slice(range.pos, range.pos + 2) === '/*' ?
            ts.SyntaxKind.MultiLineCommentTrivia :
            ts.SyntaxKind.SingleLineCommentTrivia;
        const commentRange: ts.CommentRange = {
          pos: range.pos,
          end: range.end,
          kind
        };

        this.incrementCounters(commentRange, FaultID.ErrorSuppression);
      }
    }
  }

  private processNoCheckEntry(entry: any): void {
    if (entry.range?.kind === undefined || entry.range?.pos === undefined || entry.range?.end === undefined) {
      return;
    }

    this.incrementCounters(entry.range as ts.CommentRange, FaultID.ErrorSuppression);
  }

  private reportThisKeywordsInScope(scope: ts.Block | ts.Expression): void {
    const callback = (node: ts.Node): void => {
      if (node.kind === ts.SyntaxKind.ThisKeyword) {
        this.incrementCounters(node, FaultID.FunctionContainsThis);
      }
    };
    const stopCondition = (node: ts.Node): boolean => {
      const isClassLike = ts.isClassDeclaration(node) || ts.isClassExpression(node);
      const isFunctionLike = ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node);
      const isModuleDecl = ts.isModuleDeclaration(node);
      return isClassLike || isFunctionLike || isModuleDecl;
    };
    forEachNodeInSubtree(scope, callback, stopCondition);
  }

  private handleConstructorDeclaration(node: ts.Node): void {
    const ctorDecl = node as ts.ConstructorDeclaration;
    if (ctorDecl.parameters.some((x) => {
      return TsUtils.hasAccessModifier(x);
    })) {
      let paramTypes: ts.TypeNode[] | undefined;
      if (ctorDecl.body) {
        paramTypes = this.collectCtorParamTypes(ctorDecl);
      }

      const autofix = this.autofixer?.fixCtorParameterProperties(ctorDecl, paramTypes);
      this.incrementCounters(node, FaultID.ParameterProperties, autofix);
    }
  }

  private collectCtorParamTypes(ctorDecl: ts.ConstructorDeclaration): ts.TypeNode[] | undefined {
    const paramTypes: ts.TypeNode[] = [];

    for (const param of ctorDecl.parameters) {
      let paramTypeNode = param.type;
      if (!paramTypeNode) {
        const paramType = this.tsTypeChecker.getTypeAtLocation(param);
        paramTypeNode = this.tsTypeChecker.typeToTypeNode(paramType, param, ts.NodeBuilderFlags.None);
      }
      if (!paramTypeNode || !this.tsUtils.isSupportedType(paramTypeNode)) {
        return undefined;
      }
      paramTypes.push(paramTypeNode);
    }

    return paramTypes;
  }

  private handlePrivateIdentifier(node: ts.Node): void {
    const ident = node as ts.PrivateIdentifier;
    const autofix = this.autofixer?.fixPrivateIdentifier(ident);
    this.incrementCounters(node, FaultID.PrivateIdentifier, autofix);
  }

  private handleIndexSignature(node: ts.Node): void {
    if (!this.tsUtils.isAllowedIndexSignature(node as ts.IndexSignatureDeclaration)) {
      this.incrementCounters(node, FaultID.IndexMember);
    }
  }

  private handleTypeLiteral(node: ts.Node): void {
    const typeLiteral = node as ts.TypeLiteralNode;
    const autofix = this.autofixer?.fixTypeliteral(typeLiteral);
    this.incrementCounters(node, FaultID.ObjectTypeLiteral, autofix);
  }

  private scanCapturedVarsInSendableScope(startNode: ts.Node, scope: ts.Node): void {
    const callback = (node: ts.Node): void => {
      // Namespace import will introduce closure in the es2abc compiler stage
      if (!ts.isIdentifier(node) || this.checkNamespaceImportVar(node)) {
        return;
      }

      // The "b" of "A.b" should not be checked since it's load from object "A"
      const parent: ts.Node = node.parent;
      if (ts.isPropertyAccessExpression(parent) && parent.name === node) {
        return;
      }

      this.checkLocalDecl(node, scope);
    };
    // Type nodes should not checked because no closure will be introduced
    const stopCondition = (node: ts.Node): boolean => {
      return ts.isTypeReferenceNode(node);
    };
    forEachNodeInSubtree(startNode, callback, stopCondition);
  }

  private checkLocalDecl(node: ts.Identifier, scope: ts.Node): void {
    const trueSym = this.tsUtils.trueSymbolAtLocation(node);
    // Sendable decorator should be used in method of Sendable classes
    if (trueSym === undefined) {
      return;
    }

    // Const enum member will be replaced by the exact value of it, no closure will be introduced
    if (TsUtils.isConstEnum(trueSym)) {
      return;
    }

    const declarations = trueSym.getDeclarations();
    if (declarations?.length) {
      this.checkLocalDeclWithSendableClosure(node, scope, declarations[0]);
    }
  }

  private checkLocalDeclWithSendableClosure(node: ts.Identifier, scope: ts.Node, decl: ts.Declaration): void {
    const declPosition = decl.getStart();
    if (decl.getSourceFile().fileName !== node.getSourceFile().fileName ||
        declPosition !== undefined && declPosition >= scope.getStart() && declPosition < scope.getEnd()) {
      return;
    }
    if (this.isTopSendableClosure(decl)) {
      return;
    }

    /**
     * The cases in condition will introduce closure if defined in the same file as the Sendable class. The following
     * cases are excluded because they are not allowed in ArkTS:
     * 1. ImportEqualDecalration
     * 2. BindingElement
     */
    if (ts.isVariableDeclaration(decl) || ts.isFunctionDeclaration(decl) || ts.isClassDeclaration(decl) ||
        ts.isInterfaceDeclaration(decl) || ts.isEnumDeclaration(decl) || ts.isModuleDeclaration(decl) ||
        ts.isParameter(decl)) {
      this.incrementCounters(node, FaultID.SendableCapturedVars);
    }
  }

  private isTopSendableClosure(decl: ts.Declaration): boolean {
    return (
      ts.isSourceFile(decl.parent) && ts.isClassDeclaration(decl) &&
      this.tsUtils.isSendableClassOrInterface(this.tsTypeChecker.getTypeAtLocation(decl))
    );
  }

  private checkNamespaceImportVar(node: ts.Node): boolean {
    // Namespace import cannot be determined by the true symbol
    const sym = this.tsTypeChecker.getSymbolAtLocation(node);
    const decls = sym?.getDeclarations();
    if (decls?.length) {
      if (ts.isNamespaceImport(decls[0])) {
        this.incrementCounters(node, FaultID.SendableCapturedVars);
        return true;
      }
    }
    return false;
  }

  lint(sourceFile: ts.SourceFile): void {
    if (this.enableAutofix) {
      this.autofixer = new Autofixer(this.tsTypeChecker, this.tsUtils, sourceFile, this.cancellationToken);
    }

    this.walkedComments.clear();
    this.sourceFile = sourceFile;
    this.visitSourceFile(this.sourceFile);
    this.handleCommentDirectives(this.sourceFile);
  }

  private handleExportKeyword(node: ts.Node): void {
    const parentNode = node.parent;
    if (!TypeScriptLinter.inSharedModule(node) || ts.isModuleBlock(parentNode.parent)) {
      return;
    }

    switch (parentNode.kind) {
      case ts.SyntaxKind.EnumDeclaration:
      case ts.SyntaxKind.InterfaceDeclaration:
      case ts.SyntaxKind.ClassDeclaration:
        if (!this.tsUtils.isShareableType(this.tsTypeChecker.getTypeAtLocation(parentNode))) {
          this.incrementCounters(parentNode, FaultID.SharedModuleExports);
        }
        return;
      case ts.SyntaxKind.VariableStatement:
        for (const variableDeclaration of (parentNode as ts.VariableStatement).declarationList.declarations) {
          if (!this.tsUtils.isShareableEntity(variableDeclaration.name)) {
            this.incrementCounters(variableDeclaration, FaultID.SharedModuleExports);
          }
        }
        return;
      case ts.SyntaxKind.TypeAliasDeclaration:
        return;
      default:
        this.incrementCounters(parentNode, FaultID.SharedModuleExports);
    }
  }

  private handleExportDeclaration(node: ts.Node): void {
    if (!TypeScriptLinter.inSharedModule(node) || ts.isModuleBlock(node.parent)) {
      return;
    }

    const exportDecl = node as ts.ExportDeclaration;
    if (exportDecl.exportClause === undefined) {
      this.incrementCounters(exportDecl, FaultID.SharedModuleNoWildcardExport);
      return;
    }

    if (ts.isNamespaceExport(exportDecl.exportClause)) {
      if (!this.tsUtils.isShareableType(this.tsTypeChecker.getTypeAtLocation(exportDecl.exportClause.name))) {
        this.incrementCounters(exportDecl.exportClause.name, FaultID.SharedModuleExports);
      }
      return;
    }

    for (const exportSpecifier of exportDecl.exportClause.elements) {
      if (!this.tsUtils.isShareableEntity(exportSpecifier.name)) {
        this.incrementCounters(exportSpecifier.name, FaultID.SharedModuleExports);
      }
    }
  }
}
