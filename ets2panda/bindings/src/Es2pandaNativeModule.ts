/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import * as fs from 'fs';
import * as path from 'path';
import { KNativePointer as KPtr, KInt, KBoolean, KNativePointer, KDouble, KUInt, KStringPtr } from './InteropTypes';
import { Es2pandaNativeModule as GeneratedEs2pandaNativeModule } from './generated/Es2pandaNativeModule';
import { loadNativeModuleLibrary, registerNativeModuleLibraryName } from './loadLibraries';
import { throwError } from './utils';

export type KPtrArray = BigUint64Array;

export class Es2pandaNativeModule {
  _ClassDefinitionSuper(context: KPtr, node: KPtr): KPtr {
    throw new Error('Not implemented');
  }
  _CreateTSInterfaceDeclaration(
    _context: KPtr,
    _extends: KPtrArray,
    _extendsLen: KInt,
    _id: KPtr,
    _typeParams: KPtr,
    _body: KPtr,
    _isStatic: KBoolean,
    _isExternal: KBoolean
  ): KPtr {
    throw new Error('Not implemented');
  }

  _ContextState(context: KPtr): KInt {
    throw new Error('Not implemented');
  }
  _ContextErrorMessage(context: KPtr): KPtr {
    throw new Error('Not implemented');
  }

  _AstNodeDumpModifiers(context: KPtr, node: KPtr): KPtr {
    throw new Error('Not implemented');
  }
  _CreateAstDumper(context: KPtr, node: KPtr, source: String): KPtr {
    throw new Error('Not implemented');
  }

  _CreateConfig(argc: number, argv: string[] | Uint8Array, pandaLibPath: KStringPtr): KPtr {
    throw new Error('Not implemented');
  }
  _DestroyConfig(config: KPtr): void {
    throw new Error('Not implemented');
  }
  _CreateContextFromString(config: KPtr, source: String, filename: String): KPtr {
    throw new Error('Not implemented');
  }
  _GenerateTsDeclarationsFromContext(
    config: KPtr,
    outputDeclEts: String,
    outputEts: String,
    exportAll: KBoolean
  ): KPtr {
    throw new Error('Not implemented');
  }
  _CreateContextFromFile(config: KPtr, filename: String): KPtr {
    throw new Error('Not implemented');
  }
  _DestroyContext(context: KPtr): void {
    throw new Error('Not implemented');
  }
  _ProceedToState(context: KPtr, state: number): void {
    throw new Error('Not implemented');
  }
  _ContextProgram(context: KPtr): KPtr {
    throw new Error('Not implemented');
  }
  _ProgramAst(program: KPtr): KPtr {
    throw new Error('Not implemented');
  }
  _CheckerStartChecker(context: KPtr): KBoolean {
    throw new Error('Not implemented');
  }

  _IsProgram(context: KPtr, node: KPtr): KBoolean {
    throw new Error('Not implemented');
  }
  _AstNodeDumpJsonConst(context: KPtr, node: KPtr): KPtr {
    throw new Error('Not implemented');
  }
  _AstNodeDumpEtsSrcConst(context: KPtr, node: KPtr): KPtr {
    throw new Error('Not implemented');
  }
  _AstNodeUpdateChildren(context: KPtr, node: KPtr): void {
    throw new Error('Not implemented');
  }
  _AstNodeUpdateAll(context: KPtr, node: KPtr): void {
    throw new Error('Not implemented');
  }
  _AstNodeSetOriginalNode(context: KPtr, ast: KPtr, originalNode: KPtr): void {
    throw new Error('Not implemented');
  }
  _AstNodeOriginalNodeConst(context: KPtr, ast: KPtr): KPtr {
    throw new Error('Not implemented');
  }

  _VarBinderSetProgram(context: KPtr): void {
    throw new Error('Not implemented');
  }
  _VarBinderSetContext(context: KPtr): void {
    throw new Error('Not implemented');
  }

  _getCurrentTokenValue(context: KNativePointer, position: KInt): KPtr {
    throw new Error('Not implemented');
  }

  _getSemanticDiagnostics(context: KNativePointer): KPtr {
    throw new Error('Not implemented');
  }

  _getSyntacticDiagnostics(context: KNativePointer): KPtr {
    throw new Error('Not implemented');
  }

  _getDiags(ptr: KNativePointer): KPtr {
    throw new Error('Not implemented');
  }

  _getDiagMsg(ptr: KNativePointer): KPtr {
    throw new Error('Not implemented');
  }

  _getDiagSource(ptr: KNativePointer): KPtr {
    throw new Error('Not implemented');
  }

  _getDefinitionAtPosition(context: KNativePointer, position: KInt): KPtr {
    throw new Error('Not implemented');
  }

  _getFileNameFromDef(ptr: KNativePointer): KPtr {
    throw new Error('Not implemented');
  }

  _getStartFromDef(ptr: KPtr): KInt {
    throw new Error('Not implemented');
  }

  _getLengthFromDef(ptr: KPtr): KInt {
    throw new Error('Not implemented');
  }

  _getDiagRange(ptr: KPtr): KPtr {
    throw new Error('Not implemented');
  }

  _getRangeEnd(ptr: KPtr): KPtr {
    throw new Error('Not implemented');
  }

  _getRangeStart(ptr: KPtr): KPtr {
    throw new Error('Not implemented');
  }
  _getPosLine(ptr: KPtr): KInt {
    throw new Error('Not implemented');
  }

  _getPosChar(ptr: KPtr): KInt {
    throw new Error('Not implemented');
  }

  _getDiagSeverity(ptr: KPtr): KInt {
    throw new Error('Not implemented');
  }

  _getDiagCode(ptr: KPtr): KPtr {
    throw new Error('Not implemented');
  }

  _getDiagCodeDescription(ptr: KPtr): KPtr {
    throw new Error('Not implemented');
  }

  _getCodeDescriptionHref(ptr: KPtr): KPtr {
    throw new Error('Not implemented');
  }

  _getDiagTags(ptr: KPtr): KPtr {
    throw new Error('Not implemented');
  }

  _getDiagData(ptr: KPtr): KPtr {
    throw new Error('Not implemented');
  }

  _getDiagRelatedInfo(ptr: KPtr): KPtr {
    throw new Error('Not implemented');
  }

  _getRelatedInfoMsg(ptr: KPtr): KPtr {
    throw new Error('Not implemented');
  }

  _getRelatedInfoLoc(ptr: KPtr): KPtr {
    throw new Error('Not implemented');
  }

  _getLocUri(ptr: KPtr): KPtr {
    throw new Error('Not implemented');
  }

  _getLocRange(ptr: KPtr): KPtr {
    throw new Error('Not implemented');
  }

  _getImplementationAtPosition(context: KNativePointer, position: KInt): KPtr {
    throw new Error('Not implemented');
  }

  _getReferenceStart(ptr: KPtr): KInt {
    throw new Error('Not implemented');
  }

  _getReferenceLength(ptr: KPtr): KInt {
    throw new Error('Not implemented');
  }

  _getReferenceFileName(ptr: KNativePointer): KPtr {
    throw new Error('Not implemented');
  }

  _getReferencesFromRefs(ptr: KNativePointer): KPtr[] {
    throw new Error('Not implemented');
  }

  _getReferenceInfos(ptr: KNativePointer): KPtr {
    throw new Error('Not implemented');
  }

  _getDeclInfo(context: KNativePointer, position: KInt): KPtr {
    throw new Error('Not implemented');
  }

  _getDeclInfoFileText(declInfo: KNativePointer): KPtr {
    throw new Error('Not implemented');
  }

  _getDeclInfoFileName(declInfo: KNativePointer): KPtr {
    throw new Error('Not implemented');
  }

  _getReferencesAtPosition(context: KNativePointer, declInfo: KNativePointer): KPtr {
    throw new Error('Not implemented');
  }

  _isPackageModule(context: KNativePointer): boolean {
    throw new Error('Not implemented');
  }

  _getFileReferences(filename: String, context: KNativePointer, isPackageModule: boolean): KPtr {
    throw new Error('Not implemented');
  }

  _getSpanOfEnclosingComment(filename: String, position: KInt): KPtr {
    throw new Error('Not implemented');
  }

  _getSuggestionDiagnostics(context: KNativePointer): KPtr {
    throw new Error('Not implemented');
  }

  _getQuickInfoAtPosition(filename: String, context: KNativePointer, position: KInt): KPtr {
    throw new Error('Not implemented');
  }

  _getDisplayPartsText(ptr: KNativePointer): KPtr {
    throw new Error('Not implemented');
  }

  _getDisplayPartsKind(ptr: KNativePointer): KPtr {
    throw new Error('Not implemented');
  }

  _getQuickInfoKind(ptr: KNativePointer): KPtr {
    throw new Error('Not implemented');
  }

  _getQuickInfoKindModifier(ptr: KNativePointer): KPtr {
    throw new Error('Not implemented');
  }

  _getQuickInfoFileName(ptr: KNativePointer): KPtr {
    throw new Error('Not implemented');
  }

  _getSymbolDisplayPart(ptr: KNativePointer): KPtr {
    throw new Error('Not implemented');
  }

  _getTextSpanStart(ptr: KNativePointer): KInt {
    throw new Error('Not implemented');
  }

  _getTextSpanLength(ptr: KNativePointer): KInt {
    throw new Error('Not implemented');
  }

  _getTextSpan(ptr: KNativePointer): KPtr {
    throw new Error('Not implemented');
  }

  _getHighlightTextSpan(ptr: KNativePointer): KPtr {
    throw new Error('Not implemented');
  }

  _getHighlightContextSpan(ptr: KNativePointer): KPtr {
    throw new Error('Not implemented');
  }

  _getHighlightFileName(ptr: KNativePointer): KPtr {
    throw new Error('Not implemented');
  }

  _getHighlightIsInString(ptr: KNativePointer): boolean {
    throw new Error('Not implemented');
  }

  _getHighlightKind(ptr: KPtr): KInt {
    throw new Error('Not implemented');
  }

  _getHighlightSpanFromHighlights(ptr: KNativePointer): KPtr {
    throw new Error('Not implemented');
  }

  _getDocumentHighlightsFromRef(ptr: KNativePointer): KPtr {
    throw new Error('Not implemented');
  }

  _getDocumentHighlights(context: KNativePointer, position: KInt): KPtr {
    throw new Error('Not implemented');
  }

  _getCompletionAtPosition(context: KNativePointer, position: KInt): KPtr {
    throw new Error('Not implemented');
  }

  _getFileNameFromEntryData(ptr: KNativePointer): KPtr {
    throw new Error('Not implemented');
  }

  _getNamedExportFromEntryData(ptr: KNativePointer): KPtr {
    throw new Error('Not implemented');
  }

  _getImportDeclarationFromEntryData(ptr: KNativePointer): KPtr {
    throw new Error('Not implemented');
  }

  _getStatusFromEntryData(ptr: KPtr): KInt {
    throw new Error('Not implemented');
  }

  _getNameFromEntry(ptr: KNativePointer): KPtr {
    throw new Error('Not implemented');
  }

  _getSortTextFromEntry(ptr: KNativePointer): KPtr {
    throw new Error('Not implemented');
  }

  _getInsertTextFromEntry(ptr: KNativePointer): KPtr {
    throw new Error('Not implemented');
  }

  _getKindFromEntry(ptr: KPtr): KInt {
    throw new Error('Not implemented');
  }

  _getDataFromEntry(ptr: KNativePointer): KPtr {
    throw new Error('Not implemented');
  }

  _getEntriesFromCompletionInfo(ptr: KNativePointer): KPtr {
    throw new Error('Not implemented');
  }

  _getUriFromLocation(ptr: KNativePointer): KPtr {
    throw new Error('Not implemented');
  }

  _getStartFromLocation(ptr: KNativePointer): KInt {
    throw new Error('Not implemented');
  }

  _getEndFromLocation(ptr: KNativePointer): KInt {
    throw new Error('Not implemented');
  }

  _getIsDefinitionFromLocation(ptr: KNativePointer): boolean {
    throw new Error('Not implemented');
  }

  _getIsImportFromLocation(ptr: KNativePointer): boolean {
    throw new Error('Not implemented');
  }

  _getAccessKindFromLocation(ptr: KPtr): KInt {
    throw new Error('Not implemented');
  }

  _getLocationFromList(ptr: KNativePointer): KPtr {
    throw new Error('Not implemented');
  }

  _getLine(ptr: KNativePointer): KInt {
    throw new Error('Not implemented');
  }

  _getChar(ptr: KNativePointer): KInt {
    throw new Error('Not implemented');
  }

  _toLineColumnOffset(context: KNativePointer, position: KInt): KPtr {
    throw new Error('Not implemented');
  }
}

export function initEs2panda(): Es2pandaNativeModule {
  let libPath = process.env.BINDINGS_PATH;
  if (libPath === undefined) {
    libPath = path.resolve(__dirname, '../ts_bindings.node');
  } else {
    libPath = path.join(libPath, 'ts_bindings.node');
  }
  if (!fs.existsSync(libPath)) {
    throwError(`Cannot find lib path ${libPath}`);
  }
  registerNativeModuleLibraryName('NativeModule', libPath);
  const instance = new Es2pandaNativeModule();
  loadNativeModuleLibrary('NativeModule', instance);
  return instance;
}

export function initGeneratedEs2panda(): GeneratedEs2pandaNativeModule {
  let libPath = process.env.BINDINGS_PATH;
  if (libPath === undefined) {
    libPath = path.resolve(__dirname, '../ts_bindings.node');
  } else {
    libPath = path.join(libPath, 'ts_bindings.node');
  }
  if (!fs.existsSync(libPath)) {
    throwError(`Cannot find lib path ${libPath}`);
  }
  registerNativeModuleLibraryName('NativeModule', libPath);
  const instance = new GeneratedEs2pandaNativeModule();
  loadNativeModuleLibrary('NativeModule', instance);
  return instance;
}

export function initPublicEs2panda(): Es2pandaNativeModule {
  let libPath = process.env.BINDINGS_PATH;
  if (libPath === undefined) {
    libPath = path.resolve(__dirname, '../public.node');
  } else {
    libPath = path.join(libPath, 'public.node');
  }
  if (!fs.existsSync(libPath)) {
    throwError(`Cannot find lib path ${libPath}`);
  }
  registerNativeModuleLibraryName('NativeModule', libPath);
  const instance = new Es2pandaNativeModule();
  loadNativeModuleLibrary('NativeModule', instance);
  return instance;
}

export function initPublicGeneratedEs2panda(): GeneratedEs2pandaNativeModule {
  let libPath = process.env.BINDINGS_PATH;
  if (libPath === undefined) {
    libPath = path.resolve(__dirname, '../public.node');
  } else {
    libPath = path.join(libPath, 'public.node');
  }
  if (!fs.existsSync(libPath)) {
    throwError(`Cannot find lib path ${libPath}`);
  }
  registerNativeModuleLibraryName('NativeModule', libPath);
  const instance = new GeneratedEs2pandaNativeModule();
  loadNativeModuleLibrary('NativeModule', instance);
  return instance;
}
