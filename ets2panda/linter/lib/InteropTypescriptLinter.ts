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
import * as fs from 'fs';
import * as path from 'node:path';
import * as ts from 'typescript';
import { cookBookMsg, cookBookTag } from './CookBookMsg';
import { faultsAttrs } from './FaultAttrs';
import { faultDesc } from './FaultDesc';
import { Logger } from './Logger';
import type { ProblemInfo } from './ProblemInfo';
import { ProblemSeverity } from './ProblemSeverity';
import { FaultID } from './Problems';
import { LinterConfig } from './TypeScriptLinterConfig';
import { cookBookRefToFixTitle } from './autofixes/AutofixTitles';
import type { Autofix, Autofixer } from './autofixes/Autofixer';
import { TsUtils } from './utils/TsUtils';
import { ARKTS_COLLECTIONS_D_ETS, ARKTS_LANG_D_ETS } from './utils/consts/SupportedDetsIndexableTypes';
import { D_ETS, D_TS, ETS, KIT } from './utils/consts/TsSuffix';
import { forEachNodeInSubtree } from './utils/functions/ForEachNodeInSubtree';

export function consoleLog(...args: unknown[]): void {
  if (InteropTypescriptLinter.ideMode) {
    return;
  }
  let outLine = '';
  for (let k = 0; k < args.length; k++) {
    outLine += `${args[k]} `;
  }
  Logger.info(outLine);
}

export interface KitSymbol {
  source: string;
  bindings: string;
}

export type KitSymbols = Record<string, KitSymbol>;

export interface KitInfo {
  symbols?: KitSymbols;
}

export class InteropTypescriptLinter {
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

  autofixer: Autofixer | undefined;

  private sourceFile?: ts.SourceFile;
  private isInSdk?: boolean;
  static ideMode: boolean = false;
  static testMode: boolean = false;
  static kitInfos = new Map<string, KitInfo>();
  private static etsLoaderPath?: string;
  private static sdkPath?: string;
  static useSdkLogic = false;
  static advancedClassChecks = false;

  private initCounters(): void {
    for (let i = 0; i < FaultID.LAST_ID; i++) {
      this.nodeCounters[i] = 0;
      this.lineCounters[i] = 0;
    }
  }

  constructor(
    private readonly tsTypeChecker: ts.TypeChecker,
    private readonly compileOptions: ts.CompilerOptions,
    private readonly arkts2: boolean,
    etsLoaderPath: string | undefined
  ) {
    this.tsUtils = new TsUtils(
      this.tsTypeChecker,
      InteropTypescriptLinter.testMode,
      InteropTypescriptLinter.advancedClassChecks,
      InteropTypescriptLinter.useSdkLogic,
      this.arkts2
    );
    this.currentErrorLine = 0;
    this.currentWarningLine = 0;
    InteropTypescriptLinter.etsLoaderPath = etsLoaderPath;
    InteropTypescriptLinter.sdkPath = etsLoaderPath ? path.resolve(etsLoaderPath, '../..') : undefined;
    this.initCounters();
  }

  readonly handlersMap = new Map([
    [ts.SyntaxKind.ImportDeclaration, this.handleImportDeclaration],
    [ts.SyntaxKind.InterfaceDeclaration, this.handleInterfaceDeclaration],
    [ts.SyntaxKind.ClassDeclaration, this.handleClassDeclaration],
    [ts.SyntaxKind.NewExpression, this.handleNewExpression],
    [ts.SyntaxKind.ObjectLiteralExpression, this.handleObjectLiteralExpression],
    [ts.SyntaxKind.ArrayLiteralExpression, this.handleArrayLiteralExpression],
    [ts.SyntaxKind.AsExpression, this.handleAsExpression],
    [ts.SyntaxKind.ExportDeclaration, this.handleExportDeclaration],
    [ts.SyntaxKind.ExportAssignment, this.handleExportAssignment]
  ]);

  private getLineAndCharacterOfNode(node: ts.Node | ts.CommentRange): ts.LineAndCharacter {
    const startPos = TsUtils.getStartPos(node);
    const { line, character } = this.sourceFile!.getLineAndCharacterOfPosition(startPos);
    // TSC counts lines and columns from zero
    return { line: line + 1, character: character + 1 };
  }

  incrementCounters(node: ts.Node | ts.CommentRange, faultId: number, autofix?: Autofix[]): void {
    this.nodeCounters[faultId]++;
    const { line, character } = this.getLineAndCharacterOfNode(node);
    if (InteropTypescriptLinter.ideMode) {
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
      default:
    }
  }

  private incrementCountersIdeMode(node: ts.Node | ts.CommentRange, faultId: number, autofix?: Autofix[]): void {
    if (!InteropTypescriptLinter.ideMode) {
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
      // eslint-disable-next-line no-nested-ternary
      rule: isMsgNumValid && cookBookTg !== '' ? cookBookTg : faultDescr ? faultDescr : faultType,
      ruleTag: cookBookMsgNum,
      autofix: autofix,
      autofixTitle: isMsgNumValid && autofix !== undefined ? cookBookRefToFixTitle.get(cookBookMsgNum) : undefined
    };
    this.problemsInfos.push(badNodeInfo);
  }

  private visitSourceFile(sf: ts.SourceFile): void {
    const callback = (node: ts.Node): void => {
      this.totalVisitedNodes++;

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
      if (LinterConfig.terminalTokens.has(node.kind)) {
        return true;
      }
      return false;
    };
    forEachNodeInSubtree(sf, callback, stopCondition);
  }

  private handleImportDeclaration(node: ts.Node): void {
    const importDeclaration = node as ts.ImportDeclaration;
    this.checkSendableClassorISendable(importDeclaration);
  }

  private checkSendableClassorISendable(node: ts.ImportDeclaration): void {
    const currentSourceFile = node.getSourceFile();
    const contextSpecifier = node.moduleSpecifier;
    if (!ts.isStringLiteralLike(contextSpecifier)) {
      return;
    }
    const resolvedModule = this.getResolveModule(contextSpecifier.text, currentSourceFile.fileName);
    const importClause = node.importClause;
    if (!resolvedModule) {
      return;
    }
    // handle kit
    const baseFileName = path.basename(resolvedModule.resolvedFileName);
    if (baseFileName.startsWith(KIT) && baseFileName.endsWith(D_TS)) {
      if (!InteropTypescriptLinter.etsLoaderPath) {
        return;
      }
      InteropTypescriptLinter.initKitInfos(baseFileName);

      if (!importClause) {
        return;
      }

      // skip default import
      if (importClause.name) {
        return;
      }

      if (importClause.namedBindings && ts.isNamedImports(importClause.namedBindings)) {
        this.checkKitImportClause(importClause.namedBindings, baseFileName);
      }
      return;
    }

    if (
      resolvedModule?.extension !== ETS && resolvedModule?.extension !== D_ETS ||
      TsUtils.isInImportWhiteList(resolvedModule)
    ) {
      return;
    }

    if (!importClause) {
      this.incrementCounters(node, FaultID.NoNameSpaceImportEtsToTs);
      return;
    }
    this.checkImportClause(importClause, resolvedModule);
  }

  private getResolveModule(moduleSpecifier: string, fileName: string): ts.ResolvedModuleFull | undefined {
    const resolveModuleName = ts.resolveModuleName(moduleSpecifier, fileName, this.compileOptions, ts.sys);
    return resolveModuleName.resolvedModule;
  }

  private checkKitImportClause(node: ts.NamedImports | ts.NamedExports, kitFileName: string): void {
    const length = node.elements.length;
    for (let i = 0; i < length; i++) {
      const fileName = InteropTypescriptLinter.getKitModuleFileNames(kitFileName, node, i);
      if (fileName === '' || fileName.endsWith(D_TS)) {
        continue;
      }

      const element = node.elements[i];
      const decl = this.tsUtils.getDeclarationNode(element.name);
      if (!decl) {
        continue;
      }
      if (
        ts.isModuleDeclaration(decl) && fileName !== ARKTS_COLLECTIONS_D_ETS && fileName !== ARKTS_LANG_D_ETS ||
        !this.tsUtils.isSendableClassOrInterfaceEntity(element.name)
      ) {
        this.incrementCounters(element, FaultID.NoTsImportEts);
      }
    }
  }

  private checkImportClause(node: ts.ImportClause, resolvedModule: ts.ResolvedModuleFull): void {
    const checkAndIncrement = (identifier: ts.Identifier | undefined): void => {
      if (identifier && !this.tsUtils.isSendableClassOrInterfaceEntity(identifier)) {
        this.incrementCounters(identifier, FaultID.NoTsImportEts);
      }
    };
    if (node.name) {
      if (this.allowInSdkImportSendable(resolvedModule)) {
        return;
      }
      checkAndIncrement(node.name);
    }
    if (!node.namedBindings) {
      return;
    }
    if (ts.isNamespaceImport(node.namedBindings)) {
      this.incrementCounters(node.namedBindings, FaultID.NoNameSpaceImportEtsToTs);
    } else if (ts.isNamedImports(node.namedBindings)) {
      node.namedBindings.elements.forEach((element: ts.ImportSpecifier) => {
        checkAndIncrement(element.name);
      });
    }
  }

  private allowInSdkImportSendable(resolvedModule: ts.ResolvedModuleFull): boolean {
    const resolvedModuleIsInSdk = InteropTypescriptLinter.sdkPath ?
      path.normalize(resolvedModule.resolvedFileName).startsWith(InteropTypescriptLinter.sdkPath) :
      false;
    return (
      !!this.isInSdk &&
      resolvedModuleIsInSdk &&
      path.basename(resolvedModule.resolvedFileName).indexOf('sendable') !== -1
    );
  }

  private handleClassDeclaration(node: ts.Node): void {
    const tsClassDecl = node as ts.ClassDeclaration;
    if (!tsClassDecl.heritageClauses) {
      return;
    }

    for (const hClause of tsClassDecl.heritageClauses) {
      if (hClause) {
        this.checkClassOrInterfaceDeclarationHeritageClause(hClause);
      }
    }
  }

  // In ts files, sendable classes and sendable interfaces can not be extended or implemented.
  private checkClassOrInterfaceDeclarationHeritageClause(hClause: ts.HeritageClause): void {
    for (const tsTypeExpr of hClause.types) {

      /*
       * Always resolve type from 'tsTypeExpr' node, not from 'tsTypeExpr.expression' node,
       * as for the latter, type checker will return incorrect type result for classes in
       * 'extends' clause. Additionally, reduce reference, as mostly type checker returns
       * the TypeReference type objects for classes and interfaces.
       */
      const tsExprType = TsUtils.reduceReference(this.tsTypeChecker.getTypeAtLocation(tsTypeExpr));
      const isSendableBaseType = this.tsUtils.isSendableClassOrInterface(tsExprType);
      if (isSendableBaseType) {
        this.incrementCounters(tsTypeExpr, FaultID.SendableTypeInheritance);
      }
    }
  }

  private handleInterfaceDeclaration(node: ts.Node): void {
    const interfaceNode = node as ts.InterfaceDeclaration;
    const iSymbol = this.tsUtils.trueSymbolAtLocation(interfaceNode.name);
    const iDecls = iSymbol ? iSymbol.getDeclarations() : null;
    if (!iDecls) {
      return;
    }

    if (!interfaceNode.heritageClauses) {
      return;
    }

    for (const hClause of interfaceNode.heritageClauses) {
      if (hClause) {
        this.checkClassOrInterfaceDeclarationHeritageClause(hClause);
      }
    }
  }

  private handleNewExpression(node: ts.Node): void {
    const tsNewExpr = node as ts.NewExpression;
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

  private handleObjectLiteralExpression(node: ts.Node): void {
    const objectLiteralExpr = node as ts.ObjectLiteralExpression;
    const objectLiteralType = this.tsTypeChecker.getContextualType(objectLiteralExpr);
    if (objectLiteralType && this.tsUtils.typeContainsSendableClassOrInterface(objectLiteralType)) {
      this.incrementCounters(node, FaultID.SendableObjectInitialization);
    }
  }

  private handleArrayLiteralExpression(node: ts.Node): void {
    const arrayLitNode = node as ts.ArrayLiteralExpression;
    const arrayLitType = this.tsTypeChecker.getContextualType(arrayLitNode);
    if (arrayLitType && this.tsUtils.typeContainsSendableClassOrInterface(arrayLitType)) {
      this.incrementCounters(node, FaultID.SendableObjectInitialization);
    }
  }

  private handleAsExpression(node: ts.Node): void {
    const tsAsExpr = node as ts.AsExpression;
    const targetType = this.tsTypeChecker.getTypeAtLocation(tsAsExpr.type).getNonNullableType();
    const exprType = this.tsTypeChecker.getTypeAtLocation(tsAsExpr.expression).getNonNullableType();

    if (
      !this.tsUtils.isSendableClassOrInterface(exprType) &&
      !this.tsUtils.isObject(exprType) &&
      !TsUtils.isAnyType(exprType) &&
      this.tsUtils.isSendableClassOrInterface(targetType)
    ) {
      this.incrementCounters(tsAsExpr, FaultID.SendableAsExpr);
    }
  }

  private handleExportDeclaration(node: ts.Node): void {
    const exportDecl = node as ts.ExportDeclaration;
    const currentSourceFile = exportDecl.getSourceFile();
    const contextSpecifier = exportDecl.moduleSpecifier;

    if (contextSpecifier && ts.isStringLiteralLike(contextSpecifier)) {
      const resolvedModule = this.getResolveModule(contextSpecifier.text, currentSourceFile.fileName);

      if (!resolvedModule) {
        return;
      }

      if (this.isKitModule(resolvedModule.resolvedFileName, exportDecl)) {
        return;
      }

      if (InteropTypescriptLinter.isEtsFile(resolvedModule.extension)) {
        this.incrementCounters(contextSpecifier, FaultID.NoTsReExportEts);
      }
      return;
    }

    if (!this.isInSdk) {
      return;
    }

    this.handleSdkExport(exportDecl);
  }

  private isKitModule(resolvedFileName: string, exportDecl: ts.ExportDeclaration): boolean {
    const baseFileName = path.basename(resolvedFileName);
    if (baseFileName.startsWith(KIT) && baseFileName.endsWith(D_TS)) {
      if (!InteropTypescriptLinter.etsLoaderPath) {
        return true;
      }
      InteropTypescriptLinter.initKitInfos(baseFileName);
      const exportClause = exportDecl.exportClause;

      if (exportClause && ts.isNamedExports(exportClause)) {
        this.checkKitImportClause(exportClause, baseFileName);
      }
      return true;
    }
    return false;
  }

  private static isEtsFile(extension: string | undefined): boolean {
    return extension === ETS || extension === D_ETS;
  }

  private handleSdkExport(exportDecl: ts.ExportDeclaration): void {
    if (!exportDecl.exportClause || !ts.isNamedExports(exportDecl.exportClause)) {
      return;
    }

    for (const exportSpecifier of exportDecl.exportClause.elements) {
      if (this.tsUtils.isSendableClassOrInterfaceEntity(exportSpecifier.name)) {
        this.incrementCounters(exportSpecifier.name, FaultID.SendableTypeExported);
      }
    }
  }

  private handleExportAssignment(node: ts.Node): void {
    if (!this.isInSdk) {
      return;
    }

    // In sdk .d.ts files, sendable classes and sendable interfaces can not be "default" exported.
    const exportAssignment = node as ts.ExportAssignment;

    if (this.tsUtils.isSendableClassOrInterfaceEntity(exportAssignment.expression)) {
      this.incrementCounters(exportAssignment.expression, FaultID.SendableTypeExported);
    }
  }

  private static initKitInfos(fileName: string): void {
    if (InteropTypescriptLinter.kitInfos.has(fileName)) {
      return;
    }

    const JSON_SUFFIX = '.json';
    const KIT_CONFIGS = '../ets-loader/kit_configs';
    const KIT_CONFIG_PATH = './build-tools/ets-loader/kit_configs';

    const kitConfigs: string[] = [path.resolve(InteropTypescriptLinter.etsLoaderPath as string, KIT_CONFIGS)];
    if (process.env.externalApiPaths) {
      const externalApiPaths = process.env.externalApiPaths.split(path.delimiter);
      externalApiPaths.forEach((sdkPath) => {
        kitConfigs.push(path.resolve(sdkPath, KIT_CONFIG_PATH));
      });
    }

    for (const kitConfig of kitConfigs) {
      const kitModuleConfigJson = path.resolve(kitConfig, './' + fileName.replace(D_TS, JSON_SUFFIX));
      if (fs.existsSync(kitModuleConfigJson)) {
        InteropTypescriptLinter.kitInfos.set(fileName, JSON.parse(fs.readFileSync(kitModuleConfigJson, 'utf-8')));
      }
    }
  }

  private static getKitModuleFileNames(
    fileName: string,
    node: ts.NamedImports | ts.NamedExports,
    index: number
  ): string {
    if (!InteropTypescriptLinter.kitInfos.has(fileName)) {
      return '';
    }

    const kitInfo = InteropTypescriptLinter.kitInfos.get(fileName);
    if (!kitInfo?.symbols) {
      return '';
    }

    const element = node.elements[index];
    return element.propertyName ?
      kitInfo.symbols[element.propertyName.text].source :
      kitInfo.symbols[element.name.text].source;
  }

  lint(sourceFile: ts.SourceFile): void {
    this.sourceFile = sourceFile;
    this.isInSdk = InteropTypescriptLinter.sdkPath ?
      path.normalize(this.sourceFile.fileName).indexOf(InteropTypescriptLinter.sdkPath) === 0 :
      false;
    this.visitSourceFile(this.sourceFile);
  }
}
