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
import { TsUtils, CheckType } from './utils/TsUtils';
import { FaultID } from './Problems';
import { faultsAttrs } from './FaultAttrs';
import { faultDesc } from './FaultDesc';
import { cookBookMsg, cookBookTag } from './CookBookMsg';
import { LinterConfig } from './TypeScriptLinterConfig';
import { Autofix, AutofixInfoSet } from './Autofixer';
import * as Autofixer from './Autofixer';
import { ProblemInfo } from './ProblemInfo';
import { ProblemSeverity } from './ProblemSeverity';
import Logger from '../utils/logger';
import { ARKUI_DECORATORS } from './utils/consts/ArkUIDecorators';
import { LIMITED_STD_GLOBAL_FUNC } from './utils/consts/LimitedStdGlobalFunc';
import { LIMITED_STD_GLOBAL_VAR } from './utils/consts/LimitedStdGlobalVar';
import { LIMITED_STD_OBJECT_API } from './utils/consts/LimitedStdObjectAPI';
import { LIMITED_STD_REFLECT_API } from './utils/consts/LimitedStdReflectAPI';
import { LIMITED_STD_PROXYHANDLER_API } from './utils/consts/LimitedStdProxyHandlerAPI';
import { LIMITED_STD_ARRAYBUFFER_API } from './utils/consts/LimitedStdArrayBufferAPI';
import { ALLOWED_STD_SYMBOL_API } from './utils/consts/AllowedStdSymbolAPI';
import { NON_INITIALIZABLE_PROPERTY_DECORATORS,
  NON_INITIALIZABLE_PROPERTY_CLASS_DECORATORS } from './utils/consts/NonInitializablePropertyDecorators';
import { NON_RETURN_FUNCTION_DECORATORS } from './utils/consts/NonReturnFunctionDecorators';
import { LIMITED_STANDARD_UTILITY_TYPES } from './utils/consts/LimitedStandardUtilityTypes';
import { PROPERTY_HAS_NO_INITIALIZER_ERROR_CODE } from './utils/consts/PropertyHasNoInitializerErrorCode';
import { FUNCTION_HAS_NO_RETURN_ERROR_CODE } from './utils/consts/FunctionHasNoReturnErrorCode';
import { identiferUseInValueContext } from './utils/functions/identiferUseInValueContext'
import { hasPredecessor } from './utils/functions/HasPredecessor'
import { scopeContainsThis } from './utils/functions/ContainsThis';
import { isStructDeclaration, isStruct } from './utils/functions/IsStruct';
import { isAssignmentOperator } from './utils/functions/isAssignmentOperator';
import { IncrementalLintInfo } from './IncrementalLintInfo';
import { cookBookRefToFixTitle } from './autofixes/AutofixTitles';
import { isStdLibraryType } from './utils/functions/IsStdLibrary';
import { ReportAutofixCallback } from './autofixes/ReportAutofixCallback';
import { DiagnosticChecker } from './utils/functions/DiagnosticChecker';
import {
  ARGUMENT_OF_TYPE_0_IS_NOT_ASSIGNABLE_TO_PARAMETER_OF_TYPE_1_ERROR_CODE,
  TYPE_0_IS_NOT_ASSIGNABLE_TO_TYPE_1_ERROR_CODE,
  LibraryTypeCallDiagnosticChecker
} from './utils/functions/LibraryTypeCallDiagnosticChecker';

const logger = Logger.getLogger();

export function consoleLog(...args: any[]): void {
  if (TypeScriptLinter.ideMode) {
    return;
  }
  let outLine = '';
  for (let k = 0; k < args.length; k++) {
    outLine += `${args[k]} `;
  }
  logger.info(outLine);
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
  staticBlocks: Set<string>;
  walkedComments: Set<number>;
  libraryTypeCallDiagnosticChecker: LibraryTypeCallDiagnosticChecker;

  private sourceFile?: ts.SourceFile;
  static filteredDiagnosticMessages: Set<ts.DiagnosticMessageChain>;
  static ideMode: boolean = false;
  static testMode: boolean = false;

  static advancedClassChecks = false;

  static initGlobals(): void {
    TypeScriptLinter.filteredDiagnosticMessages = new Set<ts.DiagnosticMessageChain>();
  }

  constructor(
    private tsTypeChecker: ts.TypeChecker,
    private autofixesInfo: AutofixInfoSet,
    public strictMode: boolean,
    public warningsAsErrors: boolean,
    private cancellationToken?: ts.CancellationToken,
    private incrementalLintInfo?: IncrementalLintInfo,
    private tscStrictDiagnostics?: Map<string, ts.Diagnostic[]>,
    private reportAutofixCb?: ReportAutofixCallback
  ) {
    this.tsUtils = new TsUtils(this.tsTypeChecker, TypeScriptLinter.testMode, TypeScriptLinter.advancedClassChecks);
    this.currentErrorLine = 0;
    this.currentWarningLine = 0;
    this.staticBlocks = new Set<string>();
    this.walkedComments = new Set<number>();
    this.libraryTypeCallDiagnosticChecker = new LibraryTypeCallDiagnosticChecker(TypeScriptLinter.filteredDiagnosticMessages);

    for (let i = 0; i < FaultID.LAST_ID; i++) {
      this.nodeCounters[i] = 0;
      this.lineCounters[i] = 0;
    }
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
    [ts.SyntaxKind.PropertyDeclaration, this.handlePropertyAssignmentOrDeclaration],
    [ts.SyntaxKind.PropertyAssignment, this.handlePropertyAssignmentOrDeclaration],
    [ts.SyntaxKind.FunctionExpression, this.handleFunctionExpression],
    [ts.SyntaxKind.ArrowFunction, this.handleArrowFunction],
    [ts.SyntaxKind.ClassExpression, this.handleClassExpression],
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
    [ts.SyntaxKind.ExportDeclaration, this.handleExportDeclaration],
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
  ]);

  public incrementCounters(node: ts.Node | ts.CommentRange, faultId: number, autofixable: boolean = false, autofix?: Autofix[],) {
    if (!this.strictMode && faultsAttrs[faultId].migratable) { // In relax mode skip migratable
      return;
    }
    const startPos = this.tsUtils.getStartPos(node);
    const endPos = this.tsUtils.getEndPos(node);
    const pos = this.sourceFile!.getLineAndCharacterOfPosition(endPos);
    this.nodeCounters[faultId]++;
    // TSC counts lines and columns from zero
    let { line, character } = this.sourceFile!.getLineAndCharacterOfPosition(startPos);
    ++line;
    ++character;
    let faultDescr = faultDesc[faultId];
    let faultType = LinterConfig.tsSyntaxKindNames[node.kind];
    if (TypeScriptLinter.ideMode) {
      const cookBookMsgNum = faultsAttrs[faultId] ? Number(faultsAttrs[faultId].cookBookRef) : 0;
      const cookBookTg = cookBookTag[cookBookMsgNum];
      let severity = ProblemSeverity.ERROR;
      if (faultsAttrs[faultId] && faultsAttrs[faultId].warning) {
        severity = ProblemSeverity.WARNING;
      }
      const isMsgNumValid = cookBookMsgNum > 0;
      const badNodeInfo: ProblemInfo = {
        line: line,
        column: character,
        endLine: pos.line + 1,
        endColumn: pos.character + 1,
        start: startPos,
        end: endPos,
        type: faultType,
        severity: severity,
        problem: FaultID[faultId],
        suggest: isMsgNumValid ? cookBookMsg[cookBookMsgNum] : '',
        rule: isMsgNumValid && cookBookTg !== '' ? cookBookTg : faultDescr ? faultDescr : faultType,
        ruleTag: cookBookMsgNum,
        autofixable: autofixable,
        autofix: autofix,
        autofixTitle: isMsgNumValid && autofixable ? cookBookRefToFixTitle.get(cookBookMsgNum) : undefined,
      };
      this.problemsInfos.push(badNodeInfo);
      // problems with autofixes might be collected separately
      if (this.reportAutofixCb && badNodeInfo.autofix) {
        this.reportAutofixCb(badNodeInfo);
      }
    } else {
      logger.info(
        `Warning: ${this.sourceFile!.fileName} (${line}, ${character}): ${faultDescr ? faultDescr : faultType}`
      );
    }
    this.lineCounters[faultId]++;
    if (faultsAttrs[faultId].warning) {
      if (line != this.currentWarningLine) {
        this.currentWarningLine = line;
        ++this.totalWarningLines;
        this.warningLineNumbersString += line + ', '
      }
    } else if (line != this.currentErrorLine) {
      this.currentErrorLine = line;
      ++this.totalErrorLines;
      this.errorLineNumbersString += line + ', ';
    }
  }

  private visitTSNode(node: ts.Node): void {
    const self = this;
    visitTSNodeImpl(node);
    function visitTSNodeImpl(node: ts.Node): void {
      if (node === null || node.kind === null) {
        return;
      }
      if (self.incrementalLintInfo?.shouldSkipCheck(node)) {
        return;
      }

      self.totalVisitedNodes++;
      if (isStructDeclaration(node)) {
        self.handleStructDeclaration(node);
        return;
      }
      self.handleComments(node);
      if (LinterConfig.terminalTokens.has(node.kind)) {
        return;
      }
      let incrementedType = LinterConfig.incrementOnlyTokens.get(node.kind);
      if (incrementedType !== undefined) {
        self.incrementCounters(node, incrementedType);
      } else {
        let handler = self.handlersMap.get(node.kind);
        if (handler !== undefined) {
          // possibly requested cancellation will be checked in a limited number of handlers
          // checked nodes are selected as construct nodes, similar to how TSC does
          handler.call(self, node);
        }
      }
      ts.forEachChild(node, visitTSNodeImpl);
    }
  }

  private countInterfaceExtendsDifferentPropertyTypes(
    node: ts.Node,
    prop2type: Map<string, string>,
    propName: string,
    type: ts.TypeNode | undefined
  ) {
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

  private countDeclarationsWithDuplicateName(tsNode: ts.Node, tsDeclNode: ts.Node, tsDeclKind?: ts.SyntaxKind
  ): void {
    let symbol = this.tsTypeChecker.getSymbolAtLocation(tsNode);
    // If specific declaration kind is provided, check against it.
    // Otherwise, use syntax kind of corresponding declaration node.
    if (!!symbol && this.tsUtils.symbolHasDuplicateName(symbol, tsDeclKind ?? tsDeclNode.kind)) {
      this.incrementCounters(tsDeclNode, FaultID.DeclWithDuplicateName);
    }
  }

  private countClassMembersWithDuplicateName(tsClassDecl: ts.ClassDeclaration): void {
    for (const tsCurrentMember of tsClassDecl.members) {
      if (
        !tsCurrentMember.name ||
        !(ts.isIdentifier(tsCurrentMember.name) || ts.isPrivateIdentifier(tsCurrentMember.name))
      ) {
        continue;
      }
      for (const tsClassMember of tsClassDecl.members) {
        if (tsCurrentMember === tsClassMember) {
          continue;
        }
        if (
          !tsClassMember.name ||
          !(ts.isIdentifier(tsClassMember.name) || ts.isPrivateIdentifier(tsClassMember.name))
        ) {
          continue;
        }
        if (
          ts.isIdentifier(tsCurrentMember.name) &&
          ts.isPrivateIdentifier(tsClassMember.name) &&
          tsCurrentMember.name.text === tsClassMember.name.text.substring(1)
        ) {
          this.incrementCounters(tsCurrentMember, FaultID.DeclWithDuplicateName);
          break;
        }
        if (
          ts.isPrivateIdentifier(tsCurrentMember.name) &&
          ts.isIdentifier(tsClassMember.name) &&
          tsCurrentMember.name.text.substring(1) === tsClassMember.name.text
        ) {
          this.incrementCounters(tsCurrentMember, FaultID.DeclWithDuplicateName);
          break;
        }
      }
    }
  }

  private isPrototypePropertyAccess(tsPropertyAccess: ts.PropertyAccessExpression, propAccessSym: ts.Symbol | undefined,
    baseExprSym: ts.Symbol | undefined, baseExprType: ts.Type): boolean {
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
      if (this.tsUtils.isAnyType(type)) {
        return false;
      }
    }

    // Check if property symbol is 'Prototype'
    if (this.tsUtils.isPrototypeSymbol(propAccessSym)) {
      return true;
    }
    // Check if symbol of LHS-expression is Class or Function.
    if (this.tsUtils.isTypeSymbol(baseExprSym) || this.tsUtils.isFunctionSymbol(baseExprSym)) {
      return true;
    }
    // Check if type of LHS expression Function type or Any type.
    // The latter check is to cover cases with multiple prototype
    // chain (as the 'Prototype' property should be 'Any' type):
    //      X.prototype.prototype.prototype = ...
    const baseExprTypeNode = this.tsTypeChecker.typeToTypeNode(baseExprType, undefined, ts.NodeBuilderFlags.None);
    return ((baseExprTypeNode && ts.isFunctionTypeNode(baseExprTypeNode)) || this.tsUtils.isAnyType(baseExprType));
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
          this.incrementCounters(node, FaultID.InterfaceExtendsClass);
        } else if (tsExprType.isClassOrInterface()) {
          this.lintForInterfaceExtendsDifferentPorpertyTypes(node, tsExprType, prop2type);
        }
      }
    }
  }

  private lintForInterfaceExtendsDifferentPorpertyTypes(
    node: ts.Node, tsExprType: ts.Type, prop2type: Map<string, string>
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

  private handleObjectLiteralExpression(node: ts.Node) {
    let objectLiteralExpr = node as ts.ObjectLiteralExpression;
    // If object literal is a part of destructuring assignment, then don't process it further.
    if (this.tsUtils.isDestructuringAssignmentLHS(objectLiteralExpr)) {
      return;
    }
    // issue 13082: Allow initializing struct instances with object literal.
    let objectLiteralType = this.tsTypeChecker.getContextualType(objectLiteralExpr);
    if (!this.tsUtils.isStructObjectInitializer(objectLiteralExpr) &&
        !this.tsUtils.isDynamicLiteralInitializer(objectLiteralExpr) &&
        !this.tsUtils.isExpressionAssignableToType(objectLiteralType, objectLiteralExpr)) {
      this.incrementCounters(node, FaultID.ObjectLiteralNoContextType);
    }
  }

  private handleArrayLiteralExpression(node: ts.Node) {
    // If array literal is a part of destructuring assignment, then
    // don't process it further.
    if (this.tsUtils.isDestructuringAssignmentLHS(node as ts.ArrayLiteralExpression)) {
      return;
    }
    let arrayLitNode = node as ts.ArrayLiteralExpression;
    let noContextTypeForArrayLiteral = false;
    // check that array literal consists of inferrable types
    // e.g. there is no element which is untyped object literals
    let arrayLitElements = arrayLitNode.elements;
    for(let element of arrayLitElements ) {
      if(ts.isObjectLiteralExpression(element)) {
        let objectLiteralType = this.tsTypeChecker.getContextualType(element);
        if (!this.tsUtils.isDynamicLiteralInitializer(arrayLitNode) &&
            !this.tsUtils.isExpressionAssignableToType(objectLiteralType, element)) {
          noContextTypeForArrayLiteral = true;
          break;
        }
      }
    }
    if (noContextTypeForArrayLiteral) {
      this.incrementCounters(node, FaultID.ArrayLiteralNoContextType);
    }
  }

  private handleParameter(node: ts.Node) {
    let tsParam = node as ts.ParameterDeclaration;
    if (ts.isArrayBindingPattern(tsParam.name) || ts.isObjectBindingPattern(tsParam.name)) {
      this.incrementCounters(node, FaultID.DestructuringParameter);
    }
    let tsParamMods = ts.getModifiers(tsParam);
    if (
      tsParamMods &&
      (this.tsUtils.hasModifier(tsParamMods, ts.SyntaxKind.PublicKeyword) ||
        this.tsUtils.hasModifier(tsParamMods, ts.SyntaxKind.ProtectedKeyword) ||
        this.tsUtils.hasModifier(tsParamMods, ts.SyntaxKind.ReadonlyKeyword) ||
        this.tsUtils.hasModifier(tsParamMods, ts.SyntaxKind.PrivateKeyword))
    ) {
      this.incrementCounters(node, FaultID.ParameterProperties);
    }
    this.handleDecorators(ts.getDecorators(tsParam));
    this.handleDeclarationInferredType(tsParam);
  }

  private handleEnumDeclaration(node: ts.Node) {
    let enumNode = node as ts.EnumDeclaration;
    this.countDeclarationsWithDuplicateName(enumNode.name, enumNode);
    let enumSymbol = this.tsUtils.trueSymbolAtLocation(enumNode.name);
    if (!enumSymbol) {
      return;
    }
    let enumDecls = enumSymbol.getDeclarations();
    if (!enumDecls) {
      return;
    }
    // Since type checker merges all declarations with the same name
    // into one symbol, we need to check that there's more than one
    // enum declaration related to that specific symbol.
    // See 'countDeclarationsWithDuplicateName' method for details.
    let enumDeclCount = 0;
    for (const decl of enumDecls) {
      if (decl.kind === ts.SyntaxKind.EnumDeclaration) enumDeclCount++;
    }
    if (enumDeclCount > 1) {
      this.incrementCounters(node, FaultID.EnumMerging);
    }
  }

  private handleInterfaceDeclaration(node: ts.Node) {
    // early exit via exception if cancellation was requested
    this.cancellationToken?.throwIfCancellationRequested();

    let interfaceNode = node as ts.InterfaceDeclaration;
    let iSymbol = this.tsUtils.trueSymbolAtLocation(interfaceNode.name);
    let iDecls = iSymbol ? iSymbol.getDeclarations() : null;
    if (iDecls) {
      // Since type checker merges all declarations with the same name
      // into one symbol, we need to check that there's more than one
      // interface declaration related to that specific symbol.
      // See 'countDeclarationsWithDuplicateName' method for details.
      let iDeclCount = 0;
      for (const decl of iDecls) {
        if (decl.kind === ts.SyntaxKind.InterfaceDeclaration) iDeclCount++;
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

  private handleThrowStatement(node: ts.Node) {
    let throwStmt = node as ts.ThrowStatement;
    let throwExprType = this.tsTypeChecker.getTypeAtLocation(throwStmt.expression);
    if (!throwExprType.isClassOrInterface() || !this.tsUtils.isDerivedFrom(throwExprType, CheckType.Error)) {
      this.incrementCounters(node, FaultID.ThrowStatement, false, undefined);
    }
  }

  private handleForStatement(node: ts.Node) {
    let tsForStmt = node as ts.ForStatement;
    let tsForInit = tsForStmt.initializer;
    if (tsForInit && (ts.isArrayLiteralExpression(tsForInit) || ts.isObjectLiteralExpression(tsForInit))) {
      this.incrementCounters(tsForInit, FaultID.DestructuringAssignment);
    }
  }

  private handleForInStatement(node: ts.Node) {
    let tsForInStmt = node as ts.ForInStatement;
    let tsForInInit = tsForInStmt.initializer;
    if (ts.isArrayLiteralExpression(tsForInInit) || ts.isObjectLiteralExpression(tsForInInit)) {
      this.incrementCounters(tsForInInit, FaultID.DestructuringAssignment);
    }
    this.incrementCounters(node, FaultID.ForInStatement);
  }

  private handleForOfStatement(node: ts.Node) {
    let tsForOfStmt = node as ts.ForOfStatement;
    let tsForOfInit = tsForOfStmt.initializer;
    if (ts.isArrayLiteralExpression(tsForOfInit) || ts.isObjectLiteralExpression(tsForOfInit)) {
      this.incrementCounters(tsForOfInit, FaultID.DestructuringAssignment);
    }
  }

  private handleImportDeclaration(node: ts.Node) {
    // early exit via exception if cancellation was requested
    this.cancellationToken?.throwIfCancellationRequested();

    let importDeclNode = node as ts.ImportDeclaration;
    for (const stmt of importDeclNode.parent.statements) {
      if (stmt === importDeclNode) {
        break;
      }
      if (!ts.isImportDeclaration(stmt)) {
        this.incrementCounters(node, FaultID.ImportAfterStatement);
        break;
      }
    }
    let expr1 = importDeclNode.moduleSpecifier;
    if (expr1.kind === ts.SyntaxKind.StringLiteral) {
      if (!importDeclNode.importClause) {
        this.incrementCounters(node, FaultID.ImportFromPath);
      }
      if (importDeclNode.assertClause) {
        this.incrementCounters(importDeclNode.assertClause, FaultID.ImportAssertion);
      }
    }
  }

  private handlePropertyAccessExpression(node: ts.Node) {
    if (ts.isCallExpression(node.parent) && node == node.parent.expression) {
      return;
    }

    let propertyAccessNode = node as ts.PropertyAccessExpression;

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
    if (baseExprSym !== undefined && this.tsUtils.symbolHasEsObjectType(baseExprSym)) {
      this.incrementCounters(propertyAccessNode, FaultID.EsObjectAccess);
    }
  }

  private handlePropertyAssignmentOrDeclaration(node: ts.Node) {
    let propName = (node as ts.PropertyAssignment | ts.PropertyDeclaration).name;
    if (propName && (propName.kind === ts.SyntaxKind.NumericLiteral || propName.kind === ts.SyntaxKind.StringLiteral)) {
      // We can use literals as property names only when creating Record or any interop instances.
      let isRecordObjectInitializer = false;
      let isDynamicLiteralInitializer = false;
      if (ts.isPropertyAssignment(node)) {
        let objectLiteralType = this.tsTypeChecker.getContextualType(node.parent);
        isRecordObjectInitializer = !!objectLiteralType && this.tsUtils.isStdRecordType(objectLiteralType);
        isDynamicLiteralInitializer = this.tsUtils.isDynamicLiteralInitializer(node.parent);
      }

      if (!isRecordObjectInitializer && !isDynamicLiteralInitializer) {
        let autofix : Autofix[] | undefined = Autofixer.fixLiteralAsPropertyName(node);
        let autofixable = autofix != undefined;
        if (!this.autofixesInfo.shouldAutofix(node, FaultID.LiteralAsPropertyName)) {
          autofix = undefined;
        }
        this.incrementCounters(node, FaultID.LiteralAsPropertyName, autofixable, autofix);
      }
    }
    if (ts.isPropertyDeclaration(node)) {
      const decorators = ts.getDecorators(node);
      this.handleDecorators(decorators);
      this.filterOutDecoratorsDiagnostics(decorators, NON_INITIALIZABLE_PROPERTY_DECORATORS,
        {begin: propName.getStart(), end: propName.getStart()}, PROPERTY_HAS_NO_INITIALIZER_ERROR_CODE);
      
      const classDecorators = ts.getDecorators(node.parent);
      const propType = (node as ts.PropertyDeclaration).type?.getText();
      this.filterOutDecoratorsDiagnostics(classDecorators, NON_INITIALIZABLE_PROPERTY_CLASS_DECORATORS,
        {begin: propName.getStart(), end: propName.getStart()}, PROPERTY_HAS_NO_INITIALIZER_ERROR_CODE, propType);
      this.handleDeclarationInferredType(node);
      this.handleDefiniteAssignmentAssertion(node);
    }
  }

  private filterOutDecoratorsDiagnostics(
    decorators: readonly ts.Decorator[] | undefined,
    expectedDecorators: readonly string[],
    range: {begin: number, end: number},
    code: number,
    propType?: string
  ) {
    // Filter out non-initializable property decorators from strict diagnostics.
    if (this.tscStrictDiagnostics && this.sourceFile) {
      if (decorators?.some(x => {
        let decoratorName = '';
        if (ts.isIdentifier(x.expression)) {
          decoratorName = x.expression.text;
        } else if (ts.isCallExpression(x.expression) && ts.isIdentifier(x.expression.expression)) {
          decoratorName = x.expression.expression.text;
        }
        // special case for property of type CustomDialogController of the @CustomDialog-decorated class
        if (expectedDecorators.includes(NON_INITIALIZABLE_PROPERTY_CLASS_DECORATORS[0])) {
          return expectedDecorators.includes(decoratorName) && propType === 'CustomDialogController'
        }
        return expectedDecorators.includes(decoratorName);
      })) {
        let file = path.normalize(this.sourceFile.fileName);
        let tscDiagnostics = this.tscStrictDiagnostics.get(file)
        if (tscDiagnostics) {
          let filteredDiagnostics = tscDiagnostics.filter(
            (val, idx, array) => {
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
            }
          );
          this.tscStrictDiagnostics.set(file, filteredDiagnostics);
        }
      }
    }
  }

  private checkInRange(rangesToFilter: { begin: number, end: number }[], pos: number): boolean {
    for (let i = 0; i < rangesToFilter.length; i++) {
      if (pos >= rangesToFilter[i].begin && pos < rangesToFilter[i].end) {
        return false;
      }
    }
    return true;
  }

  private filterStrictDiagnostics(filters: { [code: number]: (pos: number) => boolean },
    diagnosticChecker: DiagnosticChecker): boolean {
    if (!this.tscStrictDiagnostics || !this.sourceFile) {
      return false;
    }
    let file = path.normalize(this.sourceFile.fileName);
    let tscDiagnostics = this.tscStrictDiagnostics.get(file)
    if (!tscDiagnostics) {
      return false;
    }

    const checkDiagnostic = (val: ts.Diagnostic) => {
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

  private handleFunctionExpression(node: ts.Node) {
    const funcExpr = node as ts.FunctionExpression;
    const isGenerator = funcExpr.asteriskToken !== undefined;
    const containsThis = scopeContainsThis(funcExpr.body);
    const hasValidContext = hasPredecessor(funcExpr, ts.isClassLike) ||
                            hasPredecessor(funcExpr, ts.isInterfaceDeclaration);
    const isGeneric = funcExpr.typeParameters !== undefined && funcExpr.typeParameters.length > 0;
    const isCalledRecursively = this.tsUtils.isFunctionCalledRecursively(funcExpr);
    const [hasUnfixableReturnType, newRetTypeNode] = this.handleMissingReturnType(funcExpr);
    const autofixable = !isGeneric && !isGenerator && !containsThis && !hasUnfixableReturnType &&
      !isCalledRecursively;
    let autofix: Autofix[] | undefined;
    if (autofixable && this.autofixesInfo.shouldAutofix(node, FaultID.FunctionExpression)) {
      autofix = [ Autofixer.fixFunctionExpression(funcExpr, funcExpr.parameters, newRetTypeNode, ts.getModifiers(funcExpr)) ];
    }
    this.incrementCounters(node, FaultID.FunctionExpression, autofixable, autofix);
    if (isGeneric) {
      this.incrementCounters(funcExpr, FaultID.LambdaWithTypeParameters);
    }
    if (isGenerator) {
      this.incrementCounters(funcExpr, FaultID.GeneratorFunction);
    }
    if (containsThis && !hasValidContext) {
      this.incrementCounters(funcExpr, FaultID.FunctionContainsThis);
    }
    if (hasUnfixableReturnType) {
      this.incrementCounters(funcExpr, FaultID.LimitedReturnTypeInference);
    }
  }

  private handleArrowFunction(node: ts.Node) {
    const arrowFunc = node as ts.ArrowFunction;
    const containsThis = scopeContainsThis(arrowFunc.body);
    const hasValidContext = hasPredecessor(arrowFunc, ts.isClassLike) ||
                            hasPredecessor(arrowFunc, ts.isInterfaceDeclaration);
    if (containsThis && !hasValidContext) {
      this.incrementCounters(arrowFunc, FaultID.FunctionContainsThis);
    }
    const contextType = this.tsTypeChecker.getContextualType(arrowFunc);
    if (!(contextType && this.tsUtils.isLibraryType(contextType))) {
      if (!arrowFunc.type) {
        this.handleMissingReturnType(arrowFunc);
      }
      if (arrowFunc.typeParameters && arrowFunc.typeParameters.length > 0) {
        this.incrementCounters(node, FaultID.LambdaWithTypeParameters);
      }
    }
  }

  private handleClassExpression(node: ts.Node) {
    let tsClassExpr = node as ts.ClassExpression;
    this.incrementCounters(node, FaultID.ClassExpression);
    this.handleDecorators(ts.getDecorators(tsClassExpr));
  }

  private handleFunctionDeclaration(node: ts.Node) {
    // early exit via exception if cancellation was requested
    this.cancellationToken?.throwIfCancellationRequested();

    let tsFunctionDeclaration = node as ts.FunctionDeclaration;
    if (!tsFunctionDeclaration.type) {
      this.handleMissingReturnType(tsFunctionDeclaration);
    }
    if (tsFunctionDeclaration.name) {
      this.countDeclarationsWithDuplicateName(tsFunctionDeclaration.name, tsFunctionDeclaration);
    }
    if (tsFunctionDeclaration.body && scopeContainsThis(tsFunctionDeclaration.body)) {
      this.incrementCounters(node, FaultID.FunctionContainsThis);
    }
    if (!ts.isSourceFile(tsFunctionDeclaration.parent) && !ts.isModuleBlock(tsFunctionDeclaration.parent)) {
      this.incrementCounters(tsFunctionDeclaration, FaultID.LocalFunction);
    }
    if (tsFunctionDeclaration.asteriskToken) {
      this.incrementCounters(node, FaultID.GeneratorFunction);
    }
  }

  private handleMissingReturnType(funcLikeDecl: ts.FunctionLikeDeclaration | ts.MethodSignature): [boolean, ts.TypeNode | undefined] {
    // Note: Return type can't be inferred for function without body.
    const isSignature = ts.isMethodSignature(funcLikeDecl);
    if (isSignature || !funcLikeDecl.body) {
      // Ambient flag is not exposed, so we apply dirty hack to make it visible
      const isAmbientDeclaration = !!(funcLikeDecl.flags & (ts.NodeFlags as any)['Ambient']);
      if ((isSignature || isAmbientDeclaration) && !funcLikeDecl.type) {
        this.incrementCounters(funcLikeDecl, FaultID.LimitedReturnTypeInference);
      }
      return [false, undefined];
    }
    let autofixable = false;
    let autofix : Autofix[] | undefined;
    let newRetTypeNode: ts.TypeNode | undefined;
    let isFuncExpr = ts.isFunctionExpression(funcLikeDecl);
    // Currently, ArkTS can't infer return type of function, when expression
    // in the return statement is a call to a function or method whose return
    // value type is omitted. In that case, we attempt to prepare an autofix.
    let hasLimitedRetTypeInference = this.hasLimitedTypeInferenceFromReturnExpr(funcLikeDecl.body);
    let tsSignature = this.tsTypeChecker.getSignatureFromDeclaration(funcLikeDecl);
    if (tsSignature) {
      let tsRetType = this.tsTypeChecker.getReturnTypeOfSignature(tsSignature);
      if (!tsRetType || this.tsUtils.isUnsupportedType(tsRetType)) {
        hasLimitedRetTypeInference = true;
      } else if (hasLimitedRetTypeInference) {
        newRetTypeNode = this.tsTypeChecker.typeToTypeNode(tsRetType, funcLikeDecl, ts.NodeBuilderFlags.None);
        if (newRetTypeNode && !isFuncExpr) {
          autofixable = true;
          if (this.autofixesInfo.shouldAutofix(funcLikeDecl, FaultID.LimitedReturnTypeInference)) {
            autofix = [Autofixer.fixReturnType(funcLikeDecl, newRetTypeNode)];
          }
        }
      }
    }
    // Don't report here if in function expression context.
    // See handleFunctionExpression for details.
    if (hasLimitedRetTypeInference && !isFuncExpr) {
      this.incrementCounters(funcLikeDecl, FaultID.LimitedReturnTypeInference, autofixable, autofix);
    }
    return [hasLimitedRetTypeInference && !newRetTypeNode, newRetTypeNode];
  }

  private hasLimitedTypeInferenceFromReturnExpr(funBody: ts.ConciseBody): boolean {
    let hasLimitedTypeInference = false;
    const self = this;
    function visitNode(tsNode: ts.Node): void {
      if (hasLimitedTypeInference) {
        return;
      }
      if (
        ts.isReturnStatement(tsNode) && tsNode.expression &&
        self.tsUtils.isCallToFunctionWithOmittedReturnType(self.tsUtils.unwrapParenthesized(tsNode.expression))
      ) {
        hasLimitedTypeInference = true;
        return;
      }
      // Visit children nodes. Don't traverse other nested function-like declarations.
      if (
        !ts.isFunctionDeclaration(tsNode) &&
        !ts.isFunctionExpression(tsNode) &&
        !ts.isMethodDeclaration(tsNode) &&
        !ts.isAccessor(tsNode) &&
        !ts.isArrowFunction(tsNode)
      )
        tsNode.forEachChild(visitNode);
    }
    if (ts.isBlock(funBody)) {
      visitNode(funBody);
    } else {
      const tsExpr = this.tsUtils.unwrapParenthesized(funBody);
      hasLimitedTypeInference = this.tsUtils.isCallToFunctionWithOmittedReturnType(tsExpr);
    }
    return hasLimitedTypeInference;
  }

  private handlePrefixUnaryExpression(node: ts.Node) {
    let tsUnaryArithm = node as ts.PrefixUnaryExpression;
    let tsUnaryOp = tsUnaryArithm.operator;
    if (
      tsUnaryOp === ts.SyntaxKind.PlusToken ||
      tsUnaryOp === ts.SyntaxKind.MinusToken ||
      tsUnaryOp === ts.SyntaxKind.TildeToken
    ) {
      const tsOperatndType = this.tsTypeChecker.getTypeAtLocation(tsUnaryArithm.operand);
      if (!(tsOperatndType.getFlags() & (ts.TypeFlags.NumberLike | ts.TypeFlags.BigIntLiteral)) ||
            ( tsUnaryOp === ts.SyntaxKind.TildeToken && tsUnaryArithm.operand.kind === ts.SyntaxKind.NumericLiteral &&
              !this.tsUtils.isIntegerConstantValue(tsUnaryArithm.operand as ts.NumericLiteral) )
      )
        this.incrementCounters(node, FaultID.UnaryArithmNotNumber);
    }
  }

  private handleBinaryExpression(node: ts.Node) {
    const tsBinaryExpr = node as ts.BinaryExpression;
    const tsLhsExpr = tsBinaryExpr.left;
    const tsRhsExpr = tsBinaryExpr.right;
    if (isAssignmentOperator(tsBinaryExpr.operatorToken)) {
      this.processBinaryAssignment(node, tsLhsExpr);
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
      case ts.SyntaxKind.EqualsToken:
        if (this.tsUtils.needToDeduceStructuralIdentity(rightOperandType, leftOperandType)) {
          this.incrementCounters(tsBinaryExpr, FaultID.StructuralIdentity);
        }
        if (typeNode) {
          this.handleEsObjectAssignment(tsBinaryExpr, typeNode, tsRhsExpr);
        }
        break;
      default:
        return;
    }
  }

  private processBinaryAssignment(node: ts.Node, tsLhsExpr: ts.Expression) {
    if (ts.isObjectLiteralExpression(tsLhsExpr) || ts.isArrayLiteralExpression(tsLhsExpr)) {
      this.incrementCounters(node, FaultID.DestructuringAssignment);
    }
    if (ts.isPropertyAccessExpression(tsLhsExpr)) {
      const tsLhsSymbol = this.tsUtils.trueSymbolAtLocation(tsLhsExpr);
      const tsLhsBaseSymbol = this.tsUtils.trueSymbolAtLocation(tsLhsExpr.expression);
      if (tsLhsSymbol && (tsLhsSymbol.flags & ts.SymbolFlags.Method)) {
        this.incrementCounters(tsLhsExpr, FaultID.MethodReassignment);
      }
      if (
        this.tsUtils.isMethodAssignment(tsLhsSymbol) && tsLhsBaseSymbol &&
        (tsLhsBaseSymbol.flags & ts.SymbolFlags.Function) !== 0
      )
        this.incrementCounters(tsLhsExpr, FaultID.PropertyDeclOnFunction);
    }
  }

  private processBinaryComma(tsBinaryExpr: ts.BinaryExpression) {
    // CommaOpertor is allowed in 'for' statement initalizer and incrementor
    let tsExprNode: ts.Node = tsBinaryExpr;
    let tsParentNode = tsExprNode.parent;
    while (tsParentNode && tsParentNode.kind === ts.SyntaxKind.BinaryExpression) {
      tsExprNode = tsParentNode;
      tsParentNode = tsExprNode.parent;
    }
    if (tsParentNode && tsParentNode.kind === ts.SyntaxKind.ForStatement) {
      const tsForNode = tsParentNode as ts.ForStatement;
      if (tsExprNode === tsForNode.initializer || tsExprNode === tsForNode.incrementor) return;
    }
    this.incrementCounters(tsBinaryExpr as ts.Node, FaultID.CommaOperator);
  }

  private processBinaryInstanceOf(node: ts.Node, tsLhsExpr: ts.Expression, leftOperandType: ts.Type) {
    const leftExpr = this.tsUtils.unwrapParenthesized(tsLhsExpr);
    const leftSymbol = this.tsUtils.trueSymbolAtLocation(leftExpr);
    // In STS, the left-hand side expression may be of any reference type, otherwise
    // a compile-time error occurs. In addition, the left operand in STS cannot be a type.
    if (tsLhsExpr.kind === ts.SyntaxKind.ThisKeyword) {
      return;
    }

    if (this.tsUtils.isPrimitiveType(leftOperandType) || ts.isTypeNode(leftExpr) || this.tsUtils.isTypeSymbol(leftSymbol)) {
      this.incrementCounters(node, FaultID.InstanceofUnsupported);
    }
  }

  private handleVariableDeclarationList(node: ts.Node) {
    let varDeclFlags = ts.getCombinedNodeFlags(node);
    if (!(varDeclFlags & (ts.NodeFlags.Let | ts.NodeFlags.Const)))
      this.incrementCounters(node, FaultID.VarDeclaration);
  }

  private handleVariableDeclaration(node: ts.Node) {
    let tsVarDecl = node as ts.VariableDeclaration;
    if (ts.isArrayBindingPattern(tsVarDecl.name) || ts.isObjectBindingPattern(tsVarDecl.name))
      this.incrementCounters(node, FaultID.DestructuringDeclaration);
    {
      // Check variable declaration for duplicate name.
      const visitBindingPatternNames = (tsBindingName: ts.BindingName) => {
        if (ts.isIdentifier(tsBindingName)) {
          // The syntax kind of the declaration is defined here by the parent of 'BindingName' node.
          this.countDeclarationsWithDuplicateName(tsBindingName, tsBindingName, tsBindingName.parent.kind);
          return;
        }
        for (const tsBindingElem of tsBindingName.elements) {
          if (ts.isOmittedExpression(tsBindingElem)) continue;

          visitBindingPatternNames(tsBindingElem.name);
        }
      };
      visitBindingPatternNames(tsVarDecl.name);
    }
    if (tsVarDecl.type && tsVarDecl.initializer) {
      let tsVarInit = tsVarDecl.initializer;
      let tsVarType = this.tsTypeChecker.getTypeAtLocation(tsVarDecl.type);
      let tsInitType = this.tsTypeChecker.getTypeAtLocation(tsVarInit);
      if (this.tsUtils.needToDeduceStructuralIdentity(tsInitType, tsVarType)) {
        this.incrementCounters(tsVarDecl, FaultID.StructuralIdentity);
      }

      this.handleEsObjectAssignment(tsVarDecl, tsVarDecl.type, tsVarInit);
    }
    this.handleDeclarationInferredType(tsVarDecl);
    this.handleDefiniteAssignmentAssertion(tsVarDecl);
  }

  private handleEsObjectAssignment(node: ts.Node, type: ts.TypeNode, value: ts.Node) {
    if (!this.tsUtils.isEsObjectType(type)) {
      let valueTypeNode = this.tsUtils.getVariableDeclarationTypeNode(value);
      if (!!valueTypeNode && this.tsUtils.isEsObjectType(valueTypeNode)) {
        this.incrementCounters(node, FaultID.EsObjectAssignment);
      }

      return
    }

    if (ts.isArrayLiteralExpression(value) || ts.isObjectLiteralExpression(value)) {
      this.incrementCounters(node, FaultID.EsObjectAssignment);
      return;
    }

    const valueType = this.tsTypeChecker.getTypeAtLocation(value);
    if (this.tsUtils.isUnsupportedType(valueType)) {
      return;
    }

    if (this.tsUtils.isAnonymousType(valueType)) {
      return;
    }

    this.incrementCounters(node, FaultID.EsObjectAssignment);
  }

  private handleCatchClause(node: ts.Node) {
    let tsCatch = node as ts.CatchClause;
    // In TS catch clause doesn't permit specification of the exception varible type except 'any' or 'unknown'.
    // It is not compatible with STS 'catch' where the exception variable has to be of type
    // Error or derived from it.
    // So each 'catch' which has explicit type for the exception object goes to problems in strict mode.
    if (tsCatch.variableDeclaration && tsCatch.variableDeclaration.type) {
      let autofix: Autofix[] | undefined;
      if (this.autofixesInfo.shouldAutofix(tsCatch, FaultID.CatchWithUnsupportedType))
        autofix = [ Autofixer.dropTypeOnVarDecl(tsCatch.variableDeclaration) ];
      this.incrementCounters(node, FaultID.CatchWithUnsupportedType, true, autofix);
    }
  }

  private handleClassDeclaration(node: ts.Node) {
    // early exit via exception if cancellation was requested
    this.cancellationToken?.throwIfCancellationRequested();

    let tsClassDecl = node as ts.ClassDeclaration;
    this.staticBlocks.clear();
    if (tsClassDecl.name) {
      this.countDeclarationsWithDuplicateName(tsClassDecl.name, tsClassDecl);
    }
    this.countClassMembersWithDuplicateName(tsClassDecl);

    const visitHClause = (hClause: ts.HeritageClause) => {
      for (const tsTypeExpr of hClause.types) {
        const tsExprType = this.tsTypeChecker.getTypeAtLocation(tsTypeExpr.expression);
        if (tsExprType.isClass() && hClause.token == ts.SyntaxKind.ImplementsKeyword) {
          this.incrementCounters(tsTypeExpr, FaultID.ImplementsClass);
        }
      }
    };

    if (tsClassDecl.heritageClauses) {
      for (const hClause of tsClassDecl.heritageClauses) {
        if (!hClause) {
          continue;
        }
        visitHClause(hClause);
      }
    }
    this.handleDecorators(ts.getDecorators(tsClassDecl));
  }

  private handleModuleDeclaration(node: ts.Node) {
    // early exit via exception if cancellation was requested
    this.cancellationToken?.throwIfCancellationRequested();

    let tsModuleDecl = node as ts.ModuleDeclaration;

    this.countDeclarationsWithDuplicateName(tsModuleDecl.name, tsModuleDecl);

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
              break;
            // Nested namespace declarations are prohibited
            // but there is no cookbook recipe for it!
            case ts.SyntaxKind.ModuleDeclaration:
              break;
            default:
              this.incrementCounters(tsModuleStmt, FaultID.NonDeclarationInNamespace);
              break;
          }
        }
      }
    }

    if (!(tsModuleDecl.flags & ts.NodeFlags.Namespace) &&
        this.tsUtils.hasModifier(tsModifiers, ts.SyntaxKind.DeclareKeyword)) {
      this.incrementCounters(tsModuleDecl, FaultID.ShorthandAmbientModuleDecl);
    }

    if (ts.isStringLiteral(tsModuleDecl.name) && tsModuleDecl.name.text.includes('*'))
      this.incrementCounters(tsModuleDecl, FaultID.WildcardsInModuleName);
  }

  private handleTypeAliasDeclaration(node: ts.Node) {
    let tsTypeAlias = node as ts.TypeAliasDeclaration;
    this.countDeclarationsWithDuplicateName(tsTypeAlias.name, tsTypeAlias);
  }

  private handleImportClause(node: ts.Node) {
    let tsImportClause = node as ts.ImportClause;
    if (tsImportClause.name) {
      this.countDeclarationsWithDuplicateName(tsImportClause.name, tsImportClause);
    }
    if (tsImportClause.namedBindings && ts.isNamedImports(tsImportClause.namedBindings)) {
      let nonDefaultSpecs: ts.ImportSpecifier[] = [];
      let defaultSpec: ts.ImportSpecifier | undefined;
      for (const importSpec of tsImportClause.namedBindings.elements) {
        if (this.tsUtils.isDefaultImport(importSpec)) defaultSpec = importSpec;
        else nonDefaultSpecs.push(importSpec);
      }
      if (defaultSpec) {
        let autofix: Autofix[] | undefined;
        if (this.autofixesInfo.shouldAutofix(defaultSpec, FaultID.DefaultImport))
          autofix = [ Autofixer.fixDefaultImport(tsImportClause, defaultSpec, nonDefaultSpecs) ];
        this.incrementCounters(defaultSpec, FaultID.DefaultImport, true, autofix);
      }
    }
    if (tsImportClause.isTypeOnly) {
      let autofix: Autofix[] | undefined;
      if (this.autofixesInfo.shouldAutofix(node, FaultID.TypeOnlyImport))
        autofix = [ Autofixer.dropTypeOnlyFlag(tsImportClause) ];
      this.incrementCounters(node, FaultID.TypeOnlyImport, true, autofix);
    }
  }

  private handleImportSpecifier(node: ts.Node) {
    let importSpec = node as ts.ImportSpecifier;
    this.countDeclarationsWithDuplicateName(importSpec.name, importSpec);
    // Don't report or autofix type-only flag on default import if the latter has been autofixed already.
    if (
      importSpec.isTypeOnly &&
      (!this.tsUtils.isDefaultImport(importSpec) || !this.autofixesInfo.shouldAutofix(importSpec, FaultID.DefaultImport))
    ) {
      let autofix: Autofix[] | undefined;
      if (this.autofixesInfo.shouldAutofix(node, FaultID.TypeOnlyImport))
        autofix = [ Autofixer.dropTypeOnlyFlag(importSpec) ];
      this.incrementCounters(node, FaultID.TypeOnlyImport, true, autofix);
    }
  }

  private handleNamespaceImport(node: ts.Node) {
    let tsNamespaceImport = node as ts.NamespaceImport;
    this.countDeclarationsWithDuplicateName(tsNamespaceImport.name, tsNamespaceImport);
  }

  private handleTypeAssertionExpression(node: ts.Node) {
    let tsTypeAssertion = node as ts.TypeAssertion;
    if (tsTypeAssertion.type.getText() === 'const')
      this.incrementCounters(tsTypeAssertion, FaultID.ConstAssertion);
    else
      this.incrementCounters(node, FaultID.TypeAssertion, true, [ Autofixer.fixTypeAssertion(tsTypeAssertion) ]);
  }

  private handleMethodDeclaration(node: ts.Node) {
    const tsMethodDecl = node as ts.MethodDeclaration;
    const hasThis = scopeContainsThis(tsMethodDecl);
    let isStatic = false
    if (tsMethodDecl.modifiers) {
      for (let mod of tsMethodDecl.modifiers) {
        if (mod.kind === ts.SyntaxKind.StaticKeyword) {
          isStatic = true;
          break;
        }
      }
    }
    if (isStatic && hasThis) {
      this.incrementCounters(node, FaultID.FunctionContainsThis);
    }
    if (!tsMethodDecl.type) {
      this.handleMissingReturnType(tsMethodDecl);
    }
    if (tsMethodDecl.asteriskToken) {
      this.incrementCounters(node, FaultID.GeneratorFunction);
    }
    this.handleDecorators(ts.getDecorators(tsMethodDecl));
    this.filterOutDecoratorsDiagnostics(ts.getDecorators(tsMethodDecl), NON_RETURN_FUNCTION_DECORATORS,
      {begin: tsMethodDecl.parameters.end, end: tsMethodDecl.body?.getStart() ?? tsMethodDecl.parameters.end},
      FUNCTION_HAS_NO_RETURN_ERROR_CODE);
  }

  private handleMethodSignature(node: ts.MethodSignature) {
    const tsMethodSign = node as ts.MethodSignature;
    if (!tsMethodSign.type) {
      this.handleMissingReturnType(tsMethodSign);
    }
  }

  private handleClassStaticBlockDeclaration(node: ts.Node) {
    if (ts.isClassDeclaration(node.parent)) {
      const tsClassDecl = node.parent as ts.ClassDeclaration;
      let className = '';
      if (tsClassDecl.name)
        // May be undefined in `export default class { ... }`.
        className = tsClassDecl.name.text;
      if (scopeContainsThis(node)) {
        this.incrementCounters(node, FaultID.FunctionContainsThis);
      }
      if (this.staticBlocks.has(className))
        this.incrementCounters(node, FaultID.MultipleStaticBlocks);
      else
        this.staticBlocks.add(className);
    }
  }

  private handleIdentifier(node: ts.Node) {
    let tsIdentifier = node as ts.Identifier;
    let tsIdentSym = this.tsUtils.trueSymbolAtLocation(tsIdentifier);
    if (tsIdentSym !== undefined) {
      if (
        (tsIdentSym.flags & ts.SymbolFlags.Module) !== 0 &&
        (tsIdentSym.flags & ts.SymbolFlags.Transient) !== 0 &&
        tsIdentifier.text === 'globalThis'
      )
        this.incrementCounters(node, FaultID.GlobalThis);
      else if (this.tsUtils.isGlobalSymbol(tsIdentSym) && LIMITED_STD_GLOBAL_VAR.includes(tsIdentSym.getName()))
        this.incrementCounters(node, FaultID.LimitedStdLibApi);
      else
        this.handleRestrictedValues(tsIdentifier, tsIdentSym);
    }
  }

  // hard-coded alternative to TypeScriptLinter.advancedClassChecks
  private isAllowedClassValueContext(tsIdentifier: ts.Identifier, tsIdentSym: ts.Symbol): boolean {
    let ctx: ts.Node = tsIdentifier;
    while (ts.isPropertyAccessExpression(ctx.parent) || ts.isQualifiedName(ctx.parent)) {
      ctx = ctx.parent;
    }
    if (ts.isPropertyAssignment(ctx.parent) && ts.isObjectLiteralExpression(ctx.parent.parent)) {
      ctx = ctx.parent.parent;
    }
    if (ts.isArrowFunction(ctx.parent) && ctx.parent.body == ctx) {
      ctx = ctx.parent;
    }

    if (ts.isCallExpression(ctx.parent) || ts.isNewExpression(ctx.parent)) {
      let callee = ctx.parent.expression;
      if (callee != ctx && this.tsUtils.hasLibraryType(callee)) {
        return true;
      }
    }
    return false;
  }

  private handleRestrictedValues(tsIdentifier: ts.Identifier, tsIdentSym: ts.Symbol) {
    const illegalValues = ts.SymbolFlags.ConstEnum | ts.SymbolFlags.RegularEnum | ts.SymbolFlags.ValueModule |
      (TypeScriptLinter.advancedClassChecks? 0 : ts.SymbolFlags.Class);
    
    // If module name is duplicated by another declaration, this increases the possibility
    // of finding a lot of false positives. Thus, do not check further in that case.
    if ((tsIdentSym.flags & ts.SymbolFlags.ValueModule) != 0) {
      if (!!tsIdentSym && this.tsUtils.symbolHasDuplicateName(tsIdentSym, ts.SyntaxKind.ModuleDeclaration)) {
        return;
      }
    }

    if ((tsIdentSym.flags & illegalValues) == 0 || isStruct(tsIdentSym) || !identiferUseInValueContext(tsIdentifier, tsIdentSym)) {
      return;
    }

    if ((tsIdentSym.flags & ts.SymbolFlags.Class) != 0) {
      if (!TypeScriptLinter.advancedClassChecks && this.isAllowedClassValueContext(tsIdentifier, tsIdentSym)) {
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

  private handleElementAccessExpression(node: ts.Node) {
    const tsElementAccessExpr = node as ts.ElementAccessExpression;
    const tsElemAccessBaseExprType = this.tsTypeChecker.getTypeAtLocation(tsElementAccessExpr.expression);
    const tsElemAccessBaseExprTypeNode = this.tsTypeChecker.typeToTypeNode(tsElemAccessBaseExprType, undefined, ts.NodeBuilderFlags.None);

    const checkClassOrInterface = tsElemAccessBaseExprType.isClassOrInterface() &&
                                  !this.tsUtils.isGenericArrayType(tsElemAccessBaseExprType) &&
                                  !this.tsUtils.isDerivedFrom(tsElemAccessBaseExprType, CheckType.Array); 
    const checkThisOrSuper = this.tsUtils.isThisOrSuperExpr(tsElementAccessExpr.expression) &&
                             !this.tsUtils.isDerivedFrom(tsElemAccessBaseExprType, CheckType.Array);

    // implement check for enum argument expression

    if (
      !this.tsUtils.isLibraryType(tsElemAccessBaseExprType) && !this.tsUtils.isTypedArray(tsElemAccessBaseExprTypeNode) &&
      (checkClassOrInterface || this.tsUtils.isObjectLiteralType(tsElemAccessBaseExprType) || checkThisOrSuper)
    ) {
      let autofix = Autofixer.fixPropertyAccessByIndex(node);
      const autofixable = autofix != undefined;
      if (!this.autofixesInfo.shouldAutofix(node, FaultID.PropertyAccessByIndex))
        autofix = undefined;

      this.incrementCounters(node, FaultID.PropertyAccessByIndex, autofixable, autofix);
    }

    if (this.tsUtils.hasEsObjectType(tsElementAccessExpr.expression)) {
      this.incrementCounters(node, FaultID.EsObjectAccess);
    }
  }

  private handleEnumMember(node: ts.Node) {
    let tsEnumMember = node as ts.EnumMember;
    let tsEnumMemberType = this.tsTypeChecker.getTypeAtLocation(tsEnumMember);
    let constVal = this.tsTypeChecker.getConstantValue(tsEnumMember);
    if (tsEnumMember.initializer && !this.tsUtils.isValidEnumMemberInit(tsEnumMember.initializer))
      this.incrementCounters(node, FaultID.EnumMemberNonConstInit);
    // check for type - all members should be of same type
    let enumDecl = tsEnumMember.parent;
    let firstEnumMember = enumDecl.members[0];
    let firstEnumMemberType = this.tsTypeChecker.getTypeAtLocation(firstEnumMember);
    let firstElewmVal = this.tsTypeChecker.getConstantValue(firstEnumMember);
    // each string enum member has its own type
    // so check that value type is string
    if( constVal !==undefined && typeof constVal === 'string' &&
        firstElewmVal !==undefined && typeof firstElewmVal === 'string' )
      return;
    if( constVal !==undefined && typeof constVal === 'number' &&
      firstElewmVal !==undefined && typeof firstElewmVal === 'number' )
      return;
    if(firstEnumMemberType !== tsEnumMemberType) {
      this.incrementCounters(node, FaultID.EnumMemberNonConstInit);
    }
  }

  private handleExportDeclaration(node: ts.Node) {
    let tsExportDecl = node as ts.ExportDeclaration;
    if (tsExportDecl.isTypeOnly) {
      let autofix: Autofix[] | undefined;
      if (this.autofixesInfo.shouldAutofix(node, FaultID.TypeOnlyExport))
        autofix = [ Autofixer.dropTypeOnlyFlag(tsExportDecl) ];
      this.incrementCounters(node, FaultID.TypeOnlyExport, true, autofix);
    }
    let exportClause = tsExportDecl.exportClause;
    if (exportClause && ts.isNamedExports(exportClause)) {
      for (const exportSpec of exportClause.elements) {
        if (exportSpec.isTypeOnly) {
          let autofix: Autofix[] | undefined;
          if (this.autofixesInfo.shouldAutofix(exportSpec, FaultID.TypeOnlyExport))
            autofix = [ Autofixer.dropTypeOnlyFlag(exportSpec) ];
          this.incrementCounters(exportSpec, FaultID.TypeOnlyExport, true, autofix);
        }
      }
    }
  }

  private handleExportAssignment(node: ts.Node) {
    const exportAssignment = node as ts.ExportAssignment;
    if (exportAssignment.isExportEquals) {
      this.incrementCounters(node, FaultID.ExportAssignment);
    }
  }

  private handleCallExpression(node: ts.Node) {
    let tsCallExpr = node as ts.CallExpression;

    const calleeSym = this.tsUtils.trueSymbolAtLocation(tsCallExpr.expression);
    const calleeType = this.tsTypeChecker.getTypeAtLocation(tsCallExpr.expression);
    const callSignature = this.tsTypeChecker.getResolvedSignature(tsCallExpr);

    this.handleImportCall(tsCallExpr);
    this.handleRequireCall(tsCallExpr);
    // NOTE: Keep handleFunctionApplyBindPropCall above handleGenericCallWithNoTypeArgs here!!!
    if (calleeSym !== undefined) {
      this.handleStdlibAPICall(tsCallExpr, calleeSym);
      this.handleFunctionApplyBindPropCall(tsCallExpr, calleeSym);
      if (this.tsUtils.symbolHasEsObjectType(calleeSym)) {
        this.incrementCounters(tsCallExpr, FaultID.EsObjectAccess);
      }
    }
    if (callSignature !== undefined) {
      if (!this.tsUtils.isLibrarySymbol(calleeSym)) {
        this.handleGenericCallWithNoTypeArgs(tsCallExpr, callSignature);
      }
      this.handleStructIdentAndUndefinedInArgs(tsCallExpr, callSignature);
    }
    this.handleLibraryTypeCall(tsCallExpr, calleeType);
    
    if (ts.isPropertyAccessExpression(tsCallExpr.expression) && this.tsUtils.hasEsObjectType(tsCallExpr.expression.expression)) {
      this.incrementCounters(node, FaultID.EsObjectAccess);
    }
  }

  private handleImportCall(tsCallExpr: ts.CallExpression) {
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

  private handleRequireCall(tsCallExpr: ts.CallExpression) {
    if (
      ts.isIdentifier(tsCallExpr.expression) &&
      tsCallExpr.expression.text === 'require' &&
      ts.isVariableDeclaration(tsCallExpr.parent)
    ) {
      let tsType = this.tsTypeChecker.getTypeAtLocation(tsCallExpr.expression);
      if (this.tsUtils.isInterfaceType(tsType) && tsType.symbol.name === 'NodeRequire')
        this.incrementCounters(tsCallExpr.parent, FaultID.ImportAssignment);
    }
  }

  private handleGenericCallWithNoTypeArgs(callLikeExpr: ts.CallExpression | ts.NewExpression, callSignature: ts.Signature) {
    // Note: The PR!716 has led to a significant performance degradation.
    // Since initial problem was fixed in a more general way, this change
    // became redundant. Therefore, it was reverted. See #13721 comments 
    // for a detailed analysis. 
    const tsSyntaxKind = ts.isNewExpression(callLikeExpr) ? ts.SyntaxKind.Constructor : ts.SyntaxKind.FunctionDeclaration;
    const signFlags = ts.NodeBuilderFlags.WriteTypeArgumentsOfSignature | ts.NodeBuilderFlags.IgnoreErrors;
    const signDecl = this.tsTypeChecker.signatureToSignatureDeclaration(callSignature, tsSyntaxKind, undefined, signFlags);
    if (!signDecl?.typeArguments) {
      return;
    }
    const resolvedTypeArgs = signDecl.typeArguments;
    const startTypeArg = callLikeExpr.typeArguments?.length ?? 0;
    for (let i = startTypeArg; i < resolvedTypeArgs.length; ++i) {
      if (!this.tsUtils.isSupportedType(resolvedTypeArgs[i])) {
        this.incrementCounters(callLikeExpr, FaultID.GenericCallNoTypeArgs);
        break;
      }
    }
  }

  private static listApplyBindCallApis = [
    'Function.apply',
    'Function.call',
    'Function.bind',
    'CallableFunction.apply',
    'CallableFunction.call',
    'CallableFunction.bind'
  ];
  private handleFunctionApplyBindPropCall(tsCallExpr: ts.CallExpression, calleeSym: ts.Symbol) {
    const exprName = this.tsTypeChecker.getFullyQualifiedName(calleeSym);
    if (TypeScriptLinter.listApplyBindCallApis.includes(exprName)) {
      this.incrementCounters(tsCallExpr, FaultID.FunctionApplyBindCall);
    }
  }

  private handleStructIdentAndUndefinedInArgs(tsCallOrNewExpr: ts.CallExpression | ts.NewExpression, callSignature: ts.Signature) {
    if (!tsCallOrNewExpr.arguments) {
      return;
    }
    for (let argIndex = 0; argIndex < tsCallOrNewExpr.arguments.length; ++argIndex) {
      let tsArg = tsCallOrNewExpr.arguments[argIndex];
      let tsArgType = this.tsTypeChecker.getTypeAtLocation(tsArg);
      if (!tsArgType) {
        continue;
      }
      let paramIndex = argIndex < callSignature.parameters.length ? argIndex : callSignature.parameters.length-1;
      let tsParamSym = callSignature.parameters[paramIndex];
      if (!tsParamSym) {
        continue;
      }
      let tsParamDecl = tsParamSym.valueDeclaration;
      if (tsParamDecl && ts.isParameter(tsParamDecl)) {
        let tsParamType = this.tsTypeChecker.getTypeOfSymbolAtLocation(tsParamSym, tsParamDecl);
        if (tsParamDecl.dotDotDotToken && this.tsUtils.isGenericArrayType(tsParamType) && tsParamType.typeArguments) {
          tsParamType = tsParamType.typeArguments[0];
        }
        if (!tsParamType) {
          continue;
        }
        if (this.tsUtils.needToDeduceStructuralIdentity(tsArgType, tsParamType)) {
          this.incrementCounters(tsArg, FaultID.StructuralIdentity);
        }
      }
    }
  }

  private static LimitedApis = new Map<string, {arr: Array<string> | null, fault: FaultID}> ([
    ['global', {arr: LIMITED_STD_GLOBAL_FUNC, fault: FaultID.LimitedStdLibApi}],
    ['Object', {arr: LIMITED_STD_OBJECT_API, fault: FaultID.LimitedStdLibApi}],
    ['ObjectConstructor', {arr: LIMITED_STD_OBJECT_API, fault: FaultID.LimitedStdLibApi}],
    ['Reflect', {arr: LIMITED_STD_REFLECT_API, fault: FaultID.LimitedStdLibApi}],
    ['ProxyHandler', {arr: LIMITED_STD_PROXYHANDLER_API, fault: FaultID.LimitedStdLibApi}],
    ['ArrayBuffer', {arr: LIMITED_STD_ARRAYBUFFER_API, fault: FaultID.LimitedStdLibApi}],
    ['ArrayBufferConstructor', {arr: LIMITED_STD_ARRAYBUFFER_API, fault: FaultID.LimitedStdLibApi}],
    ['Symbol', {arr: null, fault: FaultID.SymbolType}],
    ['SymbolConstructor', {arr: null, fault: FaultID.SymbolType}],
  ])

  private handleStdlibAPICall(callExpr: ts.CallExpression, calleeSym: ts.Symbol) {
    const name = calleeSym.getName();
    const parName = this.tsUtils.getParentSymbolName(calleeSym);
    if (parName === undefined) {
      if (LIMITED_STD_GLOBAL_FUNC.includes(name)) {
        this.incrementCounters(callExpr, FaultID.LimitedStdLibApi);
        return;
      }
      let escapedName = calleeSym.escapedName;
      if (escapedName === 'Symbol' || escapedName === 'SymbolConstructor') {
        this.incrementCounters(callExpr, FaultID.SymbolType);
      }
      return;
    }
    let lookup = TypeScriptLinter.LimitedApis.get(parName);
    if (lookup !== undefined && (lookup.arr === null || lookup.arr.includes(name))) {
      this.incrementCounters(callExpr, lookup.fault);
    }
  }

  private findNonFilteringRangesFunctionCalls(callExpr: ts.CallExpression): { begin: number, end: number }[] {
    let args = callExpr.arguments;
    let result: { begin: number, end: number }[] = [];
    for (const arg of args) {
      if (ts.isArrowFunction(arg)) {
        let arrowFuncExpr = arg as ts.ArrowFunction;
        result.push({begin: arrowFuncExpr.body.pos, end: arrowFuncExpr.body.end});
      } else if (ts.isCallExpression(arg)) {
        result.push({begin: arg.arguments.pos, end: arg.arguments.end});
      }
      // there may be other cases
    }
    return result;
  }

  private handleLibraryTypeCall(callExpr: ts.CallExpression, calleeType: ts.Type) {
    let inLibCall = this.tsUtils.isLibraryType(calleeType);
    const diagnosticMessages: Array<ts.DiagnosticMessageChain> = []
    this.libraryTypeCallDiagnosticChecker.configure(inLibCall, diagnosticMessages);

    let nonFilteringRanges = this.findNonFilteringRangesFunctionCalls(callExpr);
    let rangesToFilter: { begin: number, end: number }[] = [];
    if (nonFilteringRanges.length !== 0) {
      let rangesSize = nonFilteringRanges.length;
      rangesToFilter.push({ begin: callExpr.pos, end: nonFilteringRanges[0].begin })
      rangesToFilter.push({ begin: nonFilteringRanges[rangesSize - 1].end, end: callExpr.end })
      for (let i = 0; i < rangesSize - 1; i++) {
        rangesToFilter.push({ begin: nonFilteringRanges[i].end, end: nonFilteringRanges[i + 1].begin })
      }
    } else {
      rangesToFilter.push({ begin: callExpr.pos, end: callExpr.end })
    }

    this.filterStrictDiagnostics({
        [ARGUMENT_OF_TYPE_0_IS_NOT_ASSIGNABLE_TO_PARAMETER_OF_TYPE_1_ERROR_CODE]: (pos: number) => {
          return this.checkInRange(rangesToFilter, pos);
        },
        [TYPE_0_IS_NOT_ASSIGNABLE_TO_TYPE_1_ERROR_CODE]: (pos: number) => {
          return this.checkInRange(rangesToFilter, pos);
        }
      },
      this.libraryTypeCallDiagnosticChecker
    );

    for (const msgChain of diagnosticMessages) {
      TypeScriptLinter.filteredDiagnosticMessages.add(msgChain)
    }
  }

  private handleNewExpression(node: ts.Node) {
    let tsNewExpr = node as ts.NewExpression;

    if (TypeScriptLinter.advancedClassChecks) {
      let calleeExpr = tsNewExpr.expression;
      let calleeType = this.tsTypeChecker.getTypeAtLocation(calleeExpr);
      if (!this.tsUtils.isClassTypeExrepssion(calleeExpr) && !isStdLibraryType(calleeType) &&
        !this.tsUtils.isLibraryType(calleeType) && !this.tsUtils.hasEsObjectType(calleeExpr)) {
        // missing exact rule
        this.incrementCounters(calleeExpr, FaultID.ClassAsObject);
      }
    }
    let callSignature = this.tsTypeChecker.getResolvedSignature(tsNewExpr);
    if (callSignature !== undefined) {
      this.handleStructIdentAndUndefinedInArgs(tsNewExpr, callSignature);
      this.handleGenericCallWithNoTypeArgs(tsNewExpr, callSignature);
    }
  }

  private handleAsExpression(node: ts.Node) {
    let tsAsExpr = node as ts.AsExpression;
    if (tsAsExpr.type.getText() === 'const') {
      this.incrementCounters(node, FaultID.ConstAssertion);
    }
    let targetType = this.tsTypeChecker.getTypeAtLocation(tsAsExpr.type).getNonNullableType();
    let exprType = this.tsTypeChecker.getTypeAtLocation(tsAsExpr.expression).getNonNullableType();
    if (this.tsUtils.needToDeduceStructuralIdentity(exprType, targetType, true)) {
      this.incrementCounters(tsAsExpr, FaultID.StructuralIdentity);
    }
    // check for rule#65:   'number as Number' and 'boolean as Boolean' are disabled
    if (
      ( this.tsUtils.isNumberType(exprType) && targetType.getSymbol()?.getName() === 'Number' ) ||
      ( this.tsUtils.isBooleanType(exprType) && targetType.getSymbol()?.getName() === 'Boolean' )
    ) {
      this.incrementCounters(node, FaultID.TypeAssertion);
    }
  }

  private handleTypeReference(node: ts.Node) {
    let typeRef = node as ts.TypeReferenceNode;
    if (this.tsUtils.isEsObjectType(typeRef) && !this.tsUtils.isEsObjectAllowed(typeRef)) {
      this.incrementCounters(node, FaultID.EsObjectType);
    } else if (ts.isIdentifier(typeRef.typeName) && LIMITED_STANDARD_UTILITY_TYPES.includes(typeRef.typeName.text))
      this.incrementCounters(node, FaultID.UtilityType);
    else if (
      ts.isIdentifier(typeRef.typeName) && typeRef.typeName.text === 'Partial' &&
      typeRef.typeArguments && typeRef.typeArguments.length === 1
    ) {
      // Using Partial<T> type is allowed only when its argument type is either Class or Interface.
      let argType = this.tsTypeChecker.getTypeFromTypeNode(typeRef.typeArguments[0]);
      if (!argType || !argType.isClassOrInterface())
        this.incrementCounters(node, FaultID.UtilityType);
    }
  }

  private handleMetaProperty(node: ts.Node) {
    let tsMetaProperty = node as ts.MetaProperty;
    if (tsMetaProperty.name.text === 'target')
      this.incrementCounters(node, FaultID.NewTarget);
  }

  private handleStructDeclaration(node: ts.Node) {
    // early exit via exception if cancellation was requested
    this.cancellationToken?.throwIfCancellationRequested();

    node.forEachChild(child => {
      // Skip synthetic constructor in Struct declaration.
      if (!ts.isConstructorDeclaration(child)) this.visitTSNode(child);
    });
  }

  private handleSpreadOp(node: ts.Node) {
    // spread assignment is disabled
    // spread element is allowed only for arrays as rest parameter
    if( ts.isSpreadElement(node) ) {
      let spreadElemNode = node as ts.SpreadElement;
      let spreadExprType = this.tsTypeChecker.getTypeAtLocation(spreadElemNode.expression);
      if (spreadExprType) {
        const spreadExprTypeNode = this.tsTypeChecker.typeToTypeNode(spreadExprType, undefined, ts.NodeBuilderFlags.None);
        if (spreadExprTypeNode !== undefined && (ts.isCallLikeExpression(node.parent) || ts.isArrayLiteralExpression(node.parent))) {
          if (ts.isArrayTypeNode(spreadExprTypeNode) || this.tsUtils.isTypedArray(spreadExprTypeNode) ||
            this.tsUtils.isDerivedFrom(spreadExprType, CheckType.Array)) {
            return
          }
        }
      }
    }
    this.incrementCounters(node, FaultID.SpreadOperator);
  }

  private handleConstructSignature(node: ts.Node) {
    switch (node.parent.kind) {
      case ts.SyntaxKind.TypeLiteral:
        this.incrementCounters(node, FaultID.ConstructorType);
        break;
      case ts.SyntaxKind.InterfaceDeclaration:
        this.incrementCounters(node, FaultID.ConstructorIface);
        break;
      default:
        return;
    }
  }

  private handleComments(node: ts.Node) {
    // Note: Same comment may be owned by several nodes if their
    // start/end position matches. Thus, look for the most parental
    // owner of the specific comment (by the node's position).
    const srcText = node.getSourceFile().getFullText();
    const parent = node.parent;
    if (!parent || parent.getFullStart() !== node.getFullStart()) {
      let leadingComments = ts.getLeadingCommentRanges(srcText, node.getFullStart());
      if (leadingComments) {
        for (const comment of leadingComments) {
          // In the real-time linter comment from the first line is double proccessed.
          // It may be caused by tsc, but it should be investigated. This is a workaround
          if (!this.walkedComments.has(comment.pos) && comment.pos !== comment.end) {
            this.walkedComments.add(comment.pos);
            this.checkErrorSuppressingAnnotation(comment, srcText);
          }
        }
      }
    }
    if (!parent || parent.getEnd() !== node.getEnd()) {
      let trailingComments = ts.getTrailingCommentRanges(srcText, node.getEnd());
      if (trailingComments) {
        for (const comment of trailingComments) {
          // In the real-time linter comment from the first line is double proccessed.
          // It may be caused by tsc, but it should be investigated. This is a workaround
          if (!this.walkedComments.has(comment.pos) && comment.pos !== comment.end) {
            this.walkedComments.add(comment.pos);
            this.checkErrorSuppressingAnnotation(comment, srcText);
          }
        }
      }
    }
  }

  private handleExpressionWithTypeArguments(node: ts.Node) {
    let tsTypeExpr = node as ts.ExpressionWithTypeArguments;
    let symbol = this.tsUtils.trueSymbolAtLocation(tsTypeExpr.expression);
    if (!!symbol && this.tsUtils.isEsObjectSymbol(symbol)) {
      this.incrementCounters(tsTypeExpr, FaultID.EsObjectType);
    }
  }

  private checkErrorSuppressingAnnotation(comment: ts.CommentRange, srcText: string) {
    const commentContent = comment.kind === ts.SyntaxKind.MultiLineCommentTrivia
      ? srcText.slice(comment.pos + 2, comment.end - 2)
      : srcText.slice(comment.pos + 2, comment.end);
    const trimmedContent = commentContent.trim()
    if (trimmedContent.startsWith('@ts-ignore') ||
        trimmedContent.startsWith('@ts-nocheck') || 
        trimmedContent.startsWith('@ts-expect-error'))
      this.incrementCounters(comment, FaultID.ErrorSuppression);
  }

  private handleDecorators(decorators: readonly ts.Decorator[] | undefined): void {
    if (!decorators) {
      return;
    }
    for (const decorator of decorators) {
      let decoratorName = '';
      if (ts.isIdentifier(decorator.expression)) {
        decoratorName = decorator.expression.text;
      } else if (ts.isCallExpression(decorator.expression) && ts.isIdentifier(decorator.expression.expression)) {
        decoratorName = decorator.expression.expression.text;
      }
      if (!ARKUI_DECORATORS.includes(decoratorName)) {
        this.incrementCounters(decorator, FaultID.UnsupportedDecorators);
      }
    }
  }

  private handleGetAccessor(node: ts.Node) {
    this.handleDecorators(ts.getDecorators(node as ts.GetAccessorDeclaration));
  }

  private handleSetAccessor(node: ts.Node) {
    this.handleDecorators(ts.getDecorators(node as ts.SetAccessorDeclaration));
  }

  private handleDeclarationInferredType(
    decl: ts.VariableDeclaration | ts.PropertyDeclaration | ts.ParameterDeclaration
  ) {
    // The type is explicitly specified, no need to check inferred type.
    if (decl.type) {
      return;
    }
    // issue 13161:
    // In TypeScript, the catch clause variable must be 'any' or 'unknown' type. Since
    // ArkTS doesn't support these types, the type for such variable is simply omitted,
    // and we don't report it as an error. See TypeScriptLinter.handleCatchClause()
    // for reference.
    if (ts.isCatchClause(decl.parent)) {
      return;
    }
    // Destructuring declarations are not supported, do not process them.
    if (ts.isArrayBindingPattern(decl.name) || ts.isObjectBindingPattern(decl.name)) {
      return;
    }
    const type = this.tsTypeChecker.getTypeAtLocation(decl);
    if (type) {
      this.validateDeclInferredType(type, decl);
    }
  }

  private handleDefiniteAssignmentAssertion(decl: ts.VariableDeclaration | ts.PropertyDeclaration) {
    if (decl.exclamationToken !== undefined) {
      this.incrementCounters(decl, FaultID.DefiniteAssignment);
    }
  }

  private validatedTypesSet = new Set<ts.Type>();

  private checkAnyOrUnknownChildNode(node: ts.Node): boolean {
    if (node.kind === ts.SyntaxKind.AnyKeyword ||
        node.kind === ts.SyntaxKind.UnknownKeyword) {
      return true;
    }
    for (let child of node.getChildren()) {
      if (this.checkAnyOrUnknownChildNode(child)) {
        return true;
      }
    }
    return false;
  }

  private handleInferredObjectreference(
    type: ts.Type,
    decl: ts.VariableDeclaration | ts.PropertyDeclaration | ts.ParameterDeclaration
  ) {
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
    if (type.aliasSymbol != undefined) {
      return;
    }
    const isObject = type.flags & ts.TypeFlags.Object;
    const isReference = (type as ts.ObjectType).objectFlags & ts.ObjectFlags.Reference;
    if (isObject && isReference) {
      this.handleInferredObjectreference(type, decl);
      return;
    }
    if (this.validatedTypesSet.has(type)) {
      return;
    }
    if (type.isUnion()) {
      this.validatedTypesSet.add(type);
      for (let unionElem of type.types) {
        this.validateDeclInferredType(unionElem, decl)
      }
    }
    if (this.tsUtils.isAnyType(type)) {
      this.incrementCounters(decl, FaultID.AnyType);
    } else if (this.tsUtils.isUnknownType(type)) {
      this.incrementCounters(decl, FaultID.UnknownType);
    }
  }

  public lint(sourceFile: ts.SourceFile) {
    this.walkedComments.clear();
    this.sourceFile = sourceFile;
    this.visitTSNode(this.sourceFile);
  }
}
