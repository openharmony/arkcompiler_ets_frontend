/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

import { LspDriverHelper } from './driver_helper';
import { global } from './global';
import {
  LspDefinitionData,
  LspDiagsNode,
  LspReferences,
  LspQuickInfo,
  LspClassHierarchy,
  LspCompletionEntryKind,
  LspClassPropertyInfo,
  LspClassHierarchies,
  LspDocumentHighlightsReferences,
  LspCompletionInfo,
  LspReferenceLocationList,
  LspLineAndCharacter,
  LspReferenceData,
  LspClassConstructorInfo,
  ApplicableRefactorItemInfo,
  LspApplicableRefactorInfo,
  CompletionEntryDetails,
  LspFileTextChanges,
  LspSafeDeleteLocationInfo,
  LspSafeDeleteLocation,
  LspTypeHierarchiesInfo,
  LspTextSpan,
  LspInlayHint,
  LspInlayHintList,
  TextSpan,
  LspSignatureHelpItems,
  CodeFixActionInfo,
  CodeFixActionInfoList
} from './lspNode';
import { passStringArray, unpackString } from './private';
import { Es2pandaContextState } from './generated/Es2pandaEnums';
import { BuildConfig } from './types';
import { PluginDriver, PluginHook } from './ui_plugins_driver';
import { ModuleDescriptor } from './buildConfigGenerate';
import { generateArkTsConfigByModules } from './arktsConfigGenerate';

import * as fs from 'fs';
import * as path from 'path';

const ets2pandaCmdPrefix = ['-', '--extension', 'ets', '--arktsconfig'];

function initBuildEnv(): void {
  const currentPath: string | undefined = process.env.PATH;
  let pandaLibPath: string = path.resolve(__dirname, '../../ets2panda/lib');
  process.env.PATH = `${currentPath}${path.delimiter}${pandaLibPath}`;
}

export interface TextDocumentChangeInfo {
  newDoc: string;
  rangeStart?: number;
  rangeEnd?: number;
  updateText?: string;
}

export class Lsp {
  private pandaLibPath: string;
  private projectPath: string;
  private fileNameToArktsconfig: Record<string, string>; // Map<fileName, arktsconfig.json>
  private moduleToBuildConfig: Record<string, BuildConfig>; // Map<moduleName, build_config.json>
  private getFileContent: (filePath: string) => string;
  private filesMap: Map<string, string>; // Map<fileName, fileContent>

  constructor(projectPath: string, getContentCallback?: (filePath: string) => string) {
    initBuildEnv();
    this.pandaLibPath = path.resolve(__dirname, '../../ets2panda/lib');
    this.projectPath = projectPath;
    let compileFileInfoPath = path.join(projectPath, '.idea', '.deveco', 'lsp_compileFileInfos.json');
    this.fileNameToArktsconfig = JSON.parse(fs.readFileSync(compileFileInfoPath, 'utf-8'));
    let buildConfigPath = path.join(projectPath, '.idea', '.deveco', 'lsp_build_config.json');
    this.moduleToBuildConfig = JSON.parse(fs.readFileSync(buildConfigPath, 'utf-8'));
    this.filesMap = new Map<string, string>();
    this.getFileContent = getContentCallback || ((path: string): string => fs.readFileSync(path, 'utf8'));
  }

  modifyFilesMap(fileName: string, fileContent: TextDocumentChangeInfo): void {
    this.filesMap.set(fileName, fileContent.newDoc);
  }

  deleteFromFilesMap(fileName: string): void {
    this.filesMap.delete(fileName);
  }

  updateConfig(buildSdkPath: string, modules?: ModuleDescriptor[]): void {
    generateArkTsConfigByModules(buildSdkPath, this.projectPath, modules);
    let compileFileInfoPath = path.join(this.projectPath, '.idea', '.deveco', 'lsp_compileFileInfos.json');
    this.fileNameToArktsconfig = JSON.parse(fs.readFileSync(compileFileInfoPath, 'utf-8'));
    let buildConfigPath = path.join(this.projectPath, '.idea', '.deveco', 'lsp_build_config.json');
    this.moduleToBuildConfig = JSON.parse(fs.readFileSync(buildConfigPath, 'utf-8'));
  }

  private getFileSource(filePath: string): string {
    const getSource = this.filesMap.get(filePath) || this.getFileContent(filePath);
    if (!getSource) {
      throw new Error(`File content not found for path: ${filePath}`);
    }
    return getSource.replace(/\r\n/g, '\n');
  }

  private getModuleNameFromFilename(filePath: string): string {
    const projectRoot = this.projectPath;
    if (!filePath.startsWith(projectRoot)) {
      return '';
    }
    const relativePath = path.relative(projectRoot, filePath);
    const parts = relativePath.split(path.sep);
    return parts[0] || '';
  }

  getDefinitionAtPosition(filename: String, offset: number): LspDefinitionData {
    let lspDriverHelper = new LspDriverHelper();
    let filePath = path.resolve(filename.valueOf());
    let arktsconfig = this.fileNameToArktsconfig[filePath];
    let ets2pandaCmd = ets2pandaCmdPrefix.concat(arktsconfig);
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath, this.pandaLibPath);
    const source = this.getFileSource(filePath);
    let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg);
    PluginDriver.getInstance().getPluginContext().setContextPtr(localCtx);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED);
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED);
    let ptr = global.es2panda._getDefinitionAtPosition(localCtx, offset);
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN);
    lspDriverHelper.destroyContext(localCtx);
    lspDriverHelper.destroyConfig(localCfg);
    return new LspDefinitionData(ptr);
  }

  getSemanticDiagnostics(filename: String): LspDiagsNode {
    let lspDriverHelper = new LspDriverHelper();
    let filePath = path.resolve(filename.valueOf());
    let arktsconfig = this.fileNameToArktsconfig[filePath];
    let ets2pandaCmd = ets2pandaCmdPrefix.concat(arktsconfig);
    let pandaLibPath: string = path.resolve(__dirname, '../../ets2panda/lib');
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath, pandaLibPath);
    const source = this.getFileSource(filePath);
    let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg);
    PluginDriver.getInstance().getPluginContext().setContextPtr(localCtx);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED);
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED);
    let ptr = global.es2panda._getSemanticDiagnostics(localCtx);
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN);
    lspDriverHelper.destroyContext(localCtx);
    lspDriverHelper.destroyConfig(localCfg);
    return new LspDiagsNode(ptr);
  }

  getCurrentTokenValue(filename: String, offset: number): string {
    let lspDriverHelper = new LspDriverHelper();
    let filePath = path.resolve(filename.valueOf());
    let arktsconfig = this.fileNameToArktsconfig[filePath];
    let ets2pandaCmd = ets2pandaCmdPrefix.concat(arktsconfig);
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath, this.pandaLibPath);
    const source = this.getFileSource(filePath);
    let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg);
    PluginDriver.getInstance().getPluginContext().setContextPtr(localCtx);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED);
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED);
    let ptr = global.es2panda._getCurrentTokenValue(localCtx, offset);
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN);
    lspDriverHelper.destroyContext(localCtx);
    lspDriverHelper.destroyConfig(localCfg);
    return unpackString(ptr);
  }

  getImplementationAtPosition(filename: String, offset: number): LspDefinitionData {
    let lspDriverHelper = new LspDriverHelper();
    let filePath = path.resolve(filename.valueOf());
    let arktsconfig = this.fileNameToArktsconfig[filePath];
    let ets2pandaCmd = ets2pandaCmdPrefix.concat(arktsconfig);
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath, this.pandaLibPath);
    const source = this.getFileSource(filePath);
    let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg);
    PluginDriver.getInstance().getPluginContext().setContextPtr(localCtx);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED);
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED);
    let ptr = global.es2panda._getImplementationAtPosition(localCtx, offset);
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN);
    lspDriverHelper.destroyContext(localCtx);
    lspDriverHelper.destroyConfig(localCfg);
    return new LspDefinitionData(ptr);
  }

  getFileReferences(filename: String): LspReferenceData[] {
    let lspDriverHelper = new LspDriverHelper();
    let searchFilePath = path.resolve(filename.valueOf());
    let arktsconfig = this.fileNameToArktsconfig[searchFilePath];
    let ets2pandaCmd = ets2pandaCmdPrefix.concat(arktsconfig);
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, searchFilePath, this.pandaLibPath);
    const source = this.getFileSource(searchFilePath);
    let localCtx = lspDriverHelper.createCtx(source, searchFilePath, localCfg);
    PluginDriver.getInstance().getPluginContext().setContextPtr(localCtx);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED);
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED);
    let isPackageModule = global.es2panda._isPackageModule(localCtx);
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN);
    lspDriverHelper.destroyContext(localCtx);
    lspDriverHelper.destroyConfig(localCfg);
    let result: LspReferenceData[] = [];
    let moduleName = path.basename(path.dirname(arktsconfig));
    let buildConfig: BuildConfig = this.moduleToBuildConfig[moduleName];
    for (let i = 0; i < buildConfig.compileFiles.length; i++) {
      let filePath = path.resolve(buildConfig.compileFiles[i]);
      let arktsconfig = this.fileNameToArktsconfig[filePath];
      let ets2pandaCmd = ets2pandaCmdPrefix.concat(arktsconfig);
      let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath, this.pandaLibPath);
      const source = this.getFileSource(filePath);
      let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg);
      PluginDriver.getInstance().getPluginContext().setContextPtr(localCtx);
      lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED);
      PluginDriver.getInstance().runPluginHook(PluginHook.PARSED);
      lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED);
      let ptr = global.es2panda._getFileReferences(searchFilePath, localCtx, isPackageModule);
      let refs = new LspReferences(ptr);
      PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN);
      lspDriverHelper.destroyContext(localCtx);
      lspDriverHelper.destroyConfig(localCfg);
      for (let j = 0; j < refs.referenceInfos.length; j++) {
        if (refs.referenceInfos[j].fileName !== '') {
          result.push(refs.referenceInfos[j]);
        }
      }
    }
    return result;
  }

  getReferencesAtPosition(filename: String, offset: number): LspReferenceData[] {
    let lspDriverHelper = new LspDriverHelper();
    let searchFilePath = path.resolve(filename.valueOf());
    let arktsconfig = this.fileNameToArktsconfig[searchFilePath];
    let ets2pandaCmd = ets2pandaCmdPrefix.concat(arktsconfig);
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, searchFilePath, this.pandaLibPath);
    const source = this.getFileSource(searchFilePath);
    let localCtx = lspDriverHelper.createCtx(source, searchFilePath, localCfg);
    PluginDriver.getInstance().getPluginContext().setContextPtr(localCtx);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED);
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED);
    let declInfo = global.es2panda._getDeclInfo(localCtx, offset);
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN);
    lspDriverHelper.destroyContext(localCtx);
    lspDriverHelper.destroyConfig(localCfg);
    let result: LspReferenceData[] = [];
    let moduleName = path.basename(path.dirname(arktsconfig));
    let buildConfig: BuildConfig = this.moduleToBuildConfig[moduleName];
    for (let i = 0; i < buildConfig.compileFiles.length; i++) {
      let filePath = path.resolve(buildConfig.compileFiles[i]);
      let arktsconfig = this.fileNameToArktsconfig[filePath];
      let ets2pandaCmd = ets2pandaCmdPrefix.concat(arktsconfig);
      let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath, this.pandaLibPath);
      const source = this.getFileSource(filePath);
      let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg);
      PluginDriver.getInstance().getPluginContext().setContextPtr(localCtx);
      lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED);
      PluginDriver.getInstance().runPluginHook(PluginHook.PARSED);
      lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED);
      let ptr = global.es2panda._getReferencesAtPosition(localCtx, declInfo);
      PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN);
      lspDriverHelper.destroyContext(localCtx);
      lspDriverHelper.destroyConfig(localCfg);
      let refs = new LspReferences(ptr);
      result.push(...refs.referenceInfos);
    }
    return Array.from(new Set(result));
  }

  getTypeHierarchies(filename: String, offset: number): LspTypeHierarchiesInfo | null {
    let lspDriverHelper = new LspDriverHelper();
    let filePath = path.resolve(filename.valueOf());
    let arktsconfig = this.fileNameToArktsconfig[filePath];
    let ets2pandaCmd = ets2pandaCmdPrefix.concat(arktsconfig);
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath, this.pandaLibPath);
    const source = this.getFileSource(filePath);
    let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg);
    PluginDriver.getInstance().getPluginContext().setContextPtr(localCtx);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED);
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED);
    let ptr = global.es2panda._getTypeHierarchies(localCtx, localCtx, offset);
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN);
    let ref = new LspTypeHierarchiesInfo(ptr);
    if (ref.fileName === '') {
      lspDriverHelper.destroyContext(localCtx);
      lspDriverHelper.destroyConfig(localCfg);
      return null;
    }
    let result: LspTypeHierarchiesInfo[] = [];
    let moduleName = path.basename(path.dirname(arktsconfig));
    let buildConfig: BuildConfig = this.moduleToBuildConfig[moduleName];
    for (let i = 0; i < buildConfig.compileFiles.length; i++) {
      let filePath = path.resolve(buildConfig.compileFiles[i]);
      let arktsconfig = this.fileNameToArktsconfig[filePath];
      let ets2pandaCmd = ets2pandaCmdPrefix.concat(arktsconfig);
      let searchCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath, this.pandaLibPath);
      const source = this.getFileSource(filePath);
      let searchCtx = lspDriverHelper.createCtx(source, filePath, searchCfg);
      PluginDriver.getInstance().getPluginContext().setContextPtr(searchCtx);
      lspDriverHelper.proceedToState(searchCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED);
      PluginDriver.getInstance().runPluginHook(PluginHook.PARSED);
      lspDriverHelper.proceedToState(searchCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED);
      let ptr = global.es2panda._getTypeHierarchies(searchCtx, localCtx, offset);
      PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN);
      lspDriverHelper.destroyContext(searchCtx);
      lspDriverHelper.destroyConfig(searchCfg);
      let refs = new LspTypeHierarchiesInfo(ptr);
      if (i > 0) {
        result[0].subHierarchies.subOrSuper = result[0].subHierarchies.subOrSuper.concat(refs.subHierarchies.subOrSuper);
      } else {
        result.push(refs);
      }
    }
    for (let j = 0; j < result[0].subHierarchies.subOrSuper.length; j++) {
      let res = this.getTypeHierarchies(result[0].subHierarchies.subOrSuper[j].fileName, result[0].subHierarchies.subOrSuper[j].pos);
      if (res !== null) {
        let subOrSuperTmp = result[0].subHierarchies.subOrSuper[j].subOrSuper.concat(res.subHierarchies.subOrSuper);
        result[0].subHierarchies.subOrSuper[j].subOrSuper = Array.from(
          new Map(subOrSuperTmp.map(item => [`${item.fileName}-${item.type}-${item.pos}-${item.name}`, item])).values()
        );
      }
    }
    return result[0];
  }

  getClassHierarchyInfo(filename: String, offset: number): LspClassHierarchy {
    let lspDriverHelper = new LspDriverHelper();
    let filePath = path.resolve(filename.valueOf());
    let arktsconfig = this.fileNameToArktsconfig[filePath];
    let ets2pandaCmd = ets2pandaCmdPrefix.concat(arktsconfig);
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath, this.pandaLibPath);
    const source = this.getFileContent(filePath).replace(/\r\n/g, '\n');
    let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg);
    PluginDriver.getInstance().getPluginContext().setContextPtr(localCtx);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED);
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED);
    let ptr = global.es2panda._getClassHierarchyInfo(localCtx, offset);
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN);
    lspDriverHelper.destroyContext(localCtx);
    lspDriverHelper.destroyConfig(localCfg);
    return new LspClassHierarchy(ptr);
  }

  getAliasScriptElementKind(filename: String, offset: number): LspCompletionEntryKind {
    let lspDriverHelper = new LspDriverHelper();
    let filePath = path.resolve(filename.valueOf());
    let arktsconfig = this.fileNameToArktsconfig[filePath];
    let ets2pandaCmd = ets2pandaCmdPrefix.concat(arktsconfig);
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath, this.pandaLibPath);
    const source = this.getFileContent(filePath).replace(/\r\n/g, '\n');
    let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg);
    PluginDriver.getInstance().getPluginContext().setContextPtr(localCtx);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED);
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED);
    let kind = global.es2panda._getAliasScriptElementKind(localCtx, offset);
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN);
    lspDriverHelper.destroyContext(localCtx);
    lspDriverHelper.destroyConfig(localCfg);
    return kind;
  }

  getClassHierarchies(filename: String, offset: number): LspClassHierarchies {
    let lspDriverHelper = new LspDriverHelper();
    let filePath = path.resolve(filename.valueOf());
    let arktsconfig = this.fileNameToArktsconfig[filePath];
    let ets2pandaCmd = ets2pandaCmdPrefix.concat(arktsconfig);
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath, this.pandaLibPath);
    const source = this.getFileContent(filePath).replace(/\r\n/g, '\n');
    let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg);
    PluginDriver.getInstance().getPluginContext().setContextPtr(localCtx);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED);
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED);
    let ptr = global.es2panda._getClassHierarchies(localCtx, filename, offset);
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN);
    lspDriverHelper.destroyContext(localCtx);
    lspDriverHelper.destroyConfig(localCfg);
    return new LspClassHierarchies(ptr);
  }

  getClassPropertyInfo(filename: String, offset: number, shouldCollectInherited: boolean = false): LspClassPropertyInfo {
    let lspDriverHelper = new LspDriverHelper();
    let filePath = path.resolve(filename.valueOf());
    let arktsconfig = this.fileNameToArktsconfig[filePath];
    let ets2pandaCmd = ets2pandaCmdPrefix.concat(arktsconfig);
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath, this.pandaLibPath);
    const source = this.getFileContent(filePath).replace(/\r\n/g, '\n');
    let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg);
    PluginDriver.getInstance().getPluginContext().setContextPtr(localCtx);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED);
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED);
    let ptr = global.es2panda._getClassPropertyInfo(localCtx, offset, shouldCollectInherited);
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN);
    lspDriverHelper.destroyContext(localCtx);
    lspDriverHelper.destroyConfig(localCfg);
    return new LspClassPropertyInfo(ptr);
  }

  getOrganizeImports(filename: String): LspFileTextChanges {
    let lspDriverHelper = new LspDriverHelper();
    let filePath = path.resolve(filename.valueOf());
    let arktsconfig = this.fileNameToArktsconfig[filePath];
    let ets2pandaCmd = ets2pandaCmdPrefix.concat(arktsconfig);
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath, this.pandaLibPath);
    const source = this.getFileSource(filePath);
    let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg);
    PluginDriver.getInstance().getPluginContext().setContextPtr(localCtx);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED);
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED);
    let ptr = global.es2panda._organizeImports(localCtx, filename);
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN);
    lspDriverHelper.destroyContext(localCtx);
    lspDriverHelper.destroyConfig(localCfg);
    return new LspFileTextChanges(ptr);
  }

  findSafeDeleteLocation(filename: String, offset: number): LspSafeDeleteLocationInfo[] {
    let lspDriverHelper = new LspDriverHelper();
    let filePath = path.resolve(filename.valueOf());
    let arktsconfig = this.fileNameToArktsconfig[filePath];
    let ets2pandaCmd = ets2pandaCmdPrefix.concat(arktsconfig);
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath, this.pandaLibPath);
    const source = this.getFileSource(filePath);
    let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg);
    PluginDriver.getInstance().getPluginContext().setContextPtr(localCtx);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED);
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED);
    let declInfo = global.es2panda._getDeclInfo(localCtx, offset);
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN);
    lspDriverHelper.destroyContext(localCtx);
    lspDriverHelper.destroyConfig(localCfg);
    let result: LspSafeDeleteLocationInfo[] = [];
    let moduleName = path.basename(path.dirname(arktsconfig));
    let buildConfig: BuildConfig = this.moduleToBuildConfig[moduleName];
    for (let i = 0; i < buildConfig.compileFiles.length; i++) {
      let filePath = path.resolve(buildConfig.compileFiles[i]);
      let arktsconfig = this.fileNameToArktsconfig[filePath];
      let ets2pandaCmd = ets2pandaCmdPrefix.concat(arktsconfig);
      let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath, this.pandaLibPath);
      const source = this.getFileSource(filePath);
      let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg);
      PluginDriver.getInstance().getPluginContext().setContextPtr(localCtx);
      lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED);
      PluginDriver.getInstance().runPluginHook(PluginHook.PARSED);
      lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED);
      let ptr = global.es2panda._findSafeDeleteLocation(localCtx, declInfo);
      PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN);
      lspDriverHelper.destroyContext(localCtx);
      lspDriverHelper.destroyConfig(localCfg);
      let refs = new LspSafeDeleteLocation(ptr);
      result.push(...refs.safeDeleteLocationInfos);
    }
    return Array.from(new Set(result));
  }

  getCompletionEntryDetails(filename: String, offset: number, entryName: String): CompletionEntryDetails {
    let lspDriverHelper = new LspDriverHelper();
    let filePath = path.resolve(filename.valueOf());
    let arktsconfig = this.fileNameToArktsconfig[filePath];
    let ets2pandaCmd = ets2pandaCmdPrefix.concat(arktsconfig);
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath, this.pandaLibPath);
    const source = this.getFileSource(filePath);
    let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg);
    PluginDriver.getInstance().getPluginContext().setContextPtr(localCtx);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED);
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED);
    let ptr = global.es2panda._getCompletionEntryDetails(entryName, filename, localCtx, offset);
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN);
    lspDriverHelper.destroyContext(localCtx);
    lspDriverHelper.destroyConfig(localCfg);
    return new CompletionEntryDetails(ptr);
  }

  getApplicableRefactors(filename: String, kind: String, offset: number): ApplicableRefactorItemInfo[] {
    let lspDriverHelper = new LspDriverHelper();
    let filePath = path.resolve(filename.valueOf());
    let arktsconfig = this.fileNameToArktsconfig[filePath];
    let ets2pandaCmd = ets2pandaCmdPrefix.concat(arktsconfig);
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath, this.pandaLibPath);
    const source = this.getFileSource(filePath);
    let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg);
    PluginDriver.getInstance().getPluginContext().setContextPtr(localCtx);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED);
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED);
    let result: ApplicableRefactorItemInfo[] = [];
    let ptr = global.es2panda._getApplicableRefactors(localCtx, kind, offset);
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN);
    lspDriverHelper.destroyContext(localCtx);
    lspDriverHelper.destroyConfig(localCfg);
    let refs = new LspApplicableRefactorInfo(ptr);
    result.push(...refs.applicableRefactorInfo);
    return Array.from(new Set(result));
  }

  getClassConstructorInfo(filename: String, offset: number, properties: string[]): LspClassConstructorInfo {
    let lspDriverHelper = new LspDriverHelper();
    let filePath = path.resolve(filename.valueOf());
    let arktsconfig = this.fileNameToArktsconfig[filePath];
    let ets2pandaCmd = ets2pandaCmdPrefix.concat(arktsconfig);
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath, this.pandaLibPath);
    const source = this.getFileSource(filePath);
    let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg);
    PluginDriver.getInstance().getPluginContext().setContextPtr(localCtx);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED);
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED);
    let ptr = global.es2panda._getClassConstructorInfo(localCtx, offset, passStringArray(properties));
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN);
    lspDriverHelper.destroyContext(localCtx);
    lspDriverHelper.destroyConfig(localCfg);
    return new LspClassConstructorInfo(ptr);
  }

  getSyntacticDiagnostics(filename: String): LspDiagsNode {
    let lspDriverHelper = new LspDriverHelper();
    let filePath = path.resolve(filename.valueOf());
    let arktsconfig = this.fileNameToArktsconfig[filePath];
    let ets2pandaCmd = ets2pandaCmdPrefix.concat(arktsconfig);
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath, this.pandaLibPath);
    const source = this.getFileSource(filePath);
    let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg);
    const moduleName = this.getModuleNameFromFilename(filePath);
    const buildConfig = this.moduleToBuildConfig[moduleName];
    PluginDriver.getInstance().getPluginContext().setProjectConfig(buildConfig);
    PluginDriver.getInstance().getPluginContext().setContextPtr(localCtx);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED);
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED);
    let ptr = global.es2panda._getSyntacticDiagnostics(localCtx);
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN);
    lspDriverHelper.destroyContext(localCtx);
    lspDriverHelper.destroyConfig(localCfg);
    return new LspDiagsNode(ptr);
  }

  getSuggestionDiagnostics(filename: String): LspDiagsNode {
    let lspDriverHelper = new LspDriverHelper();
    let filePath = path.resolve(filename.valueOf());
    let arktsconfig = this.fileNameToArktsconfig[filePath];
    let ets2pandaCmd = ets2pandaCmdPrefix.concat(arktsconfig);
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath, this.pandaLibPath);
    const source = this.getFileSource(filePath);
    let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg);
    PluginDriver.getInstance().getPluginContext().setContextPtr(localCtx);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED);
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED);
    let ptr = global.es2panda._getSuggestionDiagnostics(localCtx);
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN);
    lspDriverHelper.destroyContext(localCtx);
    lspDriverHelper.destroyConfig(localCfg);
    return new LspDiagsNode(ptr);
  }

  getQuickInfoAtPosition(filename: String, offset: number): LspQuickInfo {
    let lspDriverHelper = new LspDriverHelper();
    let filePath = path.resolve(filename.valueOf());
    let arktsconfig = this.fileNameToArktsconfig[filePath];
    let ets2pandaCmd = ets2pandaCmdPrefix.concat(arktsconfig);
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath, this.pandaLibPath);
    const source = this.getFileSource(filePath);
    let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg);
    PluginDriver.getInstance().getPluginContext().setContextPtr(localCtx);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED);
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED);
    let ptr = global.es2panda._getQuickInfoAtPosition(filename, localCtx, offset);
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN);
    lspDriverHelper.destroyContext(localCtx);
    lspDriverHelper.destroyConfig(localCfg);
    return new LspQuickInfo(ptr);
  }

  getDocumentHighlights(filename: String, offset: number): LspDocumentHighlightsReferences {
    let lspDriverHelper = new LspDriverHelper();
    let filePath = path.resolve(filename.valueOf());
    let arktsconfig = this.fileNameToArktsconfig[filePath];
    let ets2pandaCmd = ets2pandaCmdPrefix.concat(arktsconfig);
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath, this.pandaLibPath);
    const source = this.getFileSource(filePath);
    let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg);
    PluginDriver.getInstance().getPluginContext().setContextPtr(localCtx);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED);
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED);
    let ptr = global.es2panda._getDocumentHighlights(localCtx, offset);
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN);
    lspDriverHelper.destroyContext(localCtx);
    lspDriverHelper.destroyConfig(localCfg);
    return new LspDocumentHighlightsReferences(ptr);
  }

  getCompletionAtPosition(filename: String, offset: number): LspCompletionInfo {
    let lspDriverHelper = new LspDriverHelper();
    let filePath = path.resolve(filename.valueOf());
    let arktsconfig = this.fileNameToArktsconfig[filePath];
    let ets2pandaCmd = ets2pandaCmdPrefix.concat(arktsconfig);
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath, this.pandaLibPath);
    let source = this.getFileSource(filePath);
    // This is a temporary solution to support "obj." with wildcard for better solution in internal issue.
    if (source[offset - 1] === '.') {
      const wildcard = '_WILDCARD';
      if (offset < source.length + 1) {
        source = source.slice(0, offset) + wildcard + source.slice(offset);
      } else {
        source += wildcard;
      }
      offset += wildcard.length;
    }
    let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg);
    PluginDriver.getInstance().getPluginContext().setContextPtr(localCtx);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED);
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED);
    let ptr = global.es2panda._getCompletionAtPosition(localCtx, offset);
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN);
    lspDriverHelper.destroyContext(localCtx);
    lspDriverHelper.destroyConfig(localCfg);
    return new LspCompletionInfo(ptr);
  }

  toLineColumnOffset(filename: String, offset: number): LspLineAndCharacter {
    let lspDriverHelper = new LspDriverHelper();
    let filePath = path.resolve(filename.valueOf());
    let arktsconfig = this.fileNameToArktsconfig[filePath];
    let ets2pandaCmd = ets2pandaCmdPrefix.concat(arktsconfig);
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath, this.pandaLibPath);
    const source = this.getFileSource(filePath);
    let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg);
    PluginDriver.getInstance().getPluginContext().setContextPtr(localCtx);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED);
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED);
    let ptr = global.es2panda._toLineColumnOffset(localCtx, offset);
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN);
    lspDriverHelper.destroyContext(localCtx);
    lspDriverHelper.destroyConfig(localCfg);
    return new LspLineAndCharacter(ptr);
  }

  getSafeDeleteInfo(filename: String, position: number): boolean {
    let lspDriverHelper = new LspDriverHelper();
    let filePath = path.resolve(filename.valueOf());
    let arktsconfig = this.fileNameToArktsconfig[filePath];
    let ets2pandaCmd = ets2pandaCmdPrefix.concat(arktsconfig);
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath, this.pandaLibPath);
    const source = this.getFileSource(filePath);
    let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg);
    PluginDriver.getInstance().getPluginContext().setContextPtr(localCtx);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED);
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED);
    let result = global.es2panda._getSafeDeleteInfo(localCtx, position);
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN);
    lspDriverHelper.destroyContext(localCtx);
    lspDriverHelper.destroyConfig(localCfg);
    return result;
  }

  getSpanOfEnclosingComment(filename: String, offset: number, onlyMultiLine: boolean): LspTextSpan {
    let lspDriverHelper = new LspDriverHelper();
    let filePath = path.resolve(filename.valueOf());
    let arktsconfig = this.fileNameToArktsconfig[filePath];
    let ets2pandaCmd = ets2pandaCmdPrefix.concat(arktsconfig);
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath, this.pandaLibPath);
    const source = this.getFileSource(filePath);
    let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg);
    PluginDriver.getInstance().getPluginContext().setContextPtr(localCtx);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED);
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED);
    let ptr = global.es2panda._getSpanOfEnclosingComment(localCtx, offset, onlyMultiLine);
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN);
    lspDriverHelper.destroyContext(localCtx);
    lspDriverHelper.destroyConfig(localCfg);
    return new LspTextSpan(ptr);
  }

  getCodeFixesAtPosition(filename: String, start: number, end: number, errorCodes: number[]): CodeFixActionInfo[] {
    let lspDriverHelper = new LspDriverHelper();
    let filePath = path.resolve(filename.valueOf());
    let arktsconfig = this.fileNameToArktsconfig[filePath];
    let ets2pandaCmd = ets2pandaCmdPrefix.concat(arktsconfig);
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath, this.pandaLibPath);
    const source = this.getFileSource(filePath);
    let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg);
    PluginDriver.getInstance().getPluginContext().setContextPtr(localCtx);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED);
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED);
    let ptr = global.es2panda._getCodeFixesAtPosition(localCtx, start, end, new Int32Array(errorCodes), errorCodes.length);
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN);
    lspDriverHelper.destroyContext(localCtx);
    lspDriverHelper.destroyConfig(localCfg);
    const codeFixActionInfoList = new CodeFixActionInfoList(ptr);
    const codeFixActionInfos: CodeFixActionInfo[] = [];
    codeFixActionInfos.push(...codeFixActionInfoList.codeFixActionInfos);
    return codeFixActionInfos;
  }

  provideInlayHints(filename: String, span: TextSpan): LspInlayHint[] {
    let lspDriverHelper = new LspDriverHelper();
    let filePath = path.resolve(filename.valueOf());
    let arktsconfig = this.fileNameToArktsconfig[filePath];
    let ets2pandaCmd = ets2pandaCmdPrefix.concat(arktsconfig);
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath, this.pandaLibPath);
    const source = this.getFileSource(filePath);
    let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg);
    PluginDriver.getInstance().getPluginContext().setContextPtr(localCtx);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED);
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED);
    const nativeSpan = global.es2panda._createTextSpan(span.start, span.length);
    let ptr = global.es2panda._getInlayHintList(localCtx, nativeSpan);
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN);
    lspDriverHelper.destroyContext(localCtx);
    lspDriverHelper.destroyConfig(localCfg);
    const inlayHintList = new LspInlayHintList(ptr);
    const inlayHints: LspInlayHint[] = [];
    inlayHints.push(...inlayHintList.inlayHints);
    return inlayHints;
  }

  getSignatureHelpItems(filename: String, offset: number): LspSignatureHelpItems {
    let lspDriverHelper = new LspDriverHelper();
    let filePath = path.resolve(filename.valueOf());
    let arktsconfig = this.fileNameToArktsconfig[filePath];
    let ets2pandaCmd = ets2pandaCmdPrefix.concat(arktsconfig);
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath, this.pandaLibPath);
    const source = this.getFileSource(filePath);
    let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg);
    PluginDriver.getInstance().getPluginContext().setContextPtr(localCtx);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED);
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED);
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED);
    let ptr = global.es2panda._getSignatureHelpItems(localCtx, offset);
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN);
    lspDriverHelper.destroyContext(localCtx);
    lspDriverHelper.destroyConfig(localCfg);
    return new LspSignatureHelpItems(ptr);
  }
}
