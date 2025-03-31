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

import { LspDriverHelper } from "./driver_helper"
import { global } from "./global"
import { LspDefinitionData, LspDiagsNode, LspReferences, LspQuickInfo, LspDocumentHighlightsReferences, LspCompletionInfo, LspReferenceLocationList, LspLineAndCharacter, LspReferenceData } from "./lspNode"
import { unpackString } from "./private"
import { Es2pandaContextState } from "./generated/Es2pandaEnums"
import { BuildConfig, EtsScript } from './types'
import { PluginDriver, PluginHook } from './ui_plugins_driver'

import * as fs from "fs"
import * as path from 'path'

export class Lsp {
  private fileNameToArktsconfig: any // Map<fileName, arktsconfig.json>
  private moduleToBuildConfig: any // Map<moduleName, build_config.json>

  constructor(projectPath: string) {
    let compileFileInfoPath = path.join(projectPath, '.idea', '.deveco', 'lsp_compileFileInfos.json')
    this.fileNameToArktsconfig = JSON.parse(fs.readFileSync(compileFileInfoPath, 'utf-8'))
    let buildConfigPath = path.join(projectPath, '.idea', '.deveco', 'lsp_build_config.json')
    this.moduleToBuildConfig = JSON.parse(fs.readFileSync(buildConfigPath, 'utf-8'))
  }

  getDefinitionAtPosition(filename: String, offset: number): LspDefinitionData {
    let lspDriverHelper = new LspDriverHelper()
    let filePath = path.resolve(filename.valueOf())
    let arktsconfig = this.fileNameToArktsconfig[filePath]
    let ets2pandaCmd = ['-', '--extension', 'ets', '--arktsconfig', arktsconfig]
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath)
    const source = fs.readFileSync(filePath, 'utf8').toString().replace(/\r\n/g, '\n');
    let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg)
    PluginDriver.getInstance().getPluginContext().setArkTSProgram(localCtx.program)
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED)
    let ast = EtsScript.fromContext(localCtx)
    PluginDriver.getInstance().getPluginContext().setArkTSAst(ast)
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED)
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED)
    let ptr = global.es2panda._getDefinitionAtPosition(localCtx.peer, offset)
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN)
    lspDriverHelper.destroyContext(localCtx);
    lspDriverHelper.destroyConfig(localCfg);
    return new LspDefinitionData(ptr)
  }

  getSemanticDiagnostics(filename: String): LspDiagsNode {
    let lspDriverHelper = new LspDriverHelper()
    let filePath = path.resolve(filename.valueOf())
    let arktsconfig = this.fileNameToArktsconfig[filePath]
    let ets2pandaCmd = ['-', '--extension', 'ets', '--arktsconfig', arktsconfig]
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath)
    const source = fs.readFileSync(filePath, 'utf8').toString().replace(/\r\n/g, '\n');
    let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg)
    PluginDriver.getInstance().getPluginContext().setArkTSProgram(localCtx.program)
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED)
    let ast = EtsScript.fromContext(localCtx)
    PluginDriver.getInstance().getPluginContext().setArkTSAst(ast)
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED)
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED)
    let ptr = global.es2panda._getSemanticDiagnostics(localCtx.peer)
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN)
    lspDriverHelper.destroyContext(localCtx);
    lspDriverHelper.destroyConfig(localCfg);
    return new LspDiagsNode(ptr)
  }

  getCurrentTokenValue(filename: String, offset: number): string {
    let lspDriverHelper = new LspDriverHelper()
    let filePath = path.resolve(filename.valueOf())
    let arktsconfig = this.fileNameToArktsconfig[filePath]
    let ets2pandaCmd = ['-', '--extension', 'ets', '--arktsconfig', arktsconfig]
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath)
    const source = fs.readFileSync(filePath, 'utf8').toString().replace(/\r\n/g, '\n');
    let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg)
    PluginDriver.getInstance().getPluginContext().setArkTSProgram(localCtx.program)
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED)
    let ast = EtsScript.fromContext(localCtx)
    PluginDriver.getInstance().getPluginContext().setArkTSAst(ast)
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED)
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED)
    let ptr = global.es2panda._getCurrentTokenValue(localCtx.peer, offset)
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN)
    lspDriverHelper.destroyContext(localCtx);
    lspDriverHelper.destroyConfig(localCfg);
    return unpackString(ptr)
  }

  getImplementationAtPosition(filename: String, offset: number): LspDefinitionData {
    let lspDriverHelper = new LspDriverHelper()
    let filePath = path.resolve(filename.valueOf())
    let arktsconfig = this.fileNameToArktsconfig[filePath]
    let ets2pandaCmd = ['-', '--extension', 'ets', '--arktsconfig', arktsconfig]
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath)
    const source = fs.readFileSync(filePath, 'utf8').toString().replace(/\r\n/g, '\n');
    let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg)
    PluginDriver.getInstance().getPluginContext().setArkTSProgram(localCtx.program)
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED)
    let ast = EtsScript.fromContext(localCtx)
    PluginDriver.getInstance().getPluginContext().setArkTSAst(ast)
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED)
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED)
    let ptr = global.es2panda._getImplementationAtPosition(localCtx.peer, offset)
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN)
    lspDriverHelper.destroyContext(localCtx);
    lspDriverHelper.destroyConfig(localCfg);
    return new LspDefinitionData(ptr)
  }

  getFileReferences(filename: String): LspReferenceData[] {
    let lspDriverHelper = new LspDriverHelper()
    let filePath = path.resolve(filename.valueOf())
    let arktsconfig = this.fileNameToArktsconfig[filePath]
    let ets2pandaCmd = ['-', '--extension', 'ets', '--arktsconfig', arktsconfig]
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath)
    const source = fs.readFileSync(filePath, 'utf8').toString().replace(/\r\n/g, '\n');
    let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg)
    PluginDriver.getInstance().getPluginContext().setArkTSProgram(localCtx.program)
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED)
    let ast = EtsScript.fromContext(localCtx)
    PluginDriver.getInstance().getPluginContext().setArkTSAst(ast)
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED)
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED)
    let isPackageModule = global.es2panda._isPackageModule(localCtx.peer)
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN)
    lspDriverHelper.destroyContext(localCtx);
    lspDriverHelper.destroyConfig(localCfg);
    let result: LspReferenceData[] = []
    let moduleName = path.basename(path.dirname(arktsconfig))
    let buildConfig: BuildConfig = this.moduleToBuildConfig[moduleName]
    for (let i = 0; i < buildConfig.compileFiles.length; i++) {
      let filePath = path.resolve(buildConfig.compileFiles[i])
      let arktsconfig = this.fileNameToArktsconfig[filePath]
      let ets2pandaCmd = ['-', '--extension', 'ets', '--arktsconfig', arktsconfig]
      let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath)
      const source = fs.readFileSync(filePath, 'utf8').toString().replace(/\r\n/g, '\n');
      let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg)
      PluginDriver.getInstance().getPluginContext().setArkTSProgram(localCtx.program)
      lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED)
      let ast = EtsScript.fromContext(localCtx)
      PluginDriver.getInstance().getPluginContext().setArkTSAst(ast)
      PluginDriver.getInstance().runPluginHook(PluginHook.PARSED)
      lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED)
      let ptr = global.es2panda._getFileReferences(filePath, localCtx.peer, isPackageModule)
      let refs = new LspReferences(ptr)
      PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN)
      lspDriverHelper.destroyContext(localCtx)
      lspDriverHelper.destroyConfig(localCfg)
      for (let j = 0; j < refs.referenceInfos.length; j++) {
        if (refs.referenceInfos[j].fileName !== '') {
          result.push(refs.referenceInfos[j])
        }
      }
    }
    return result
  }

  getReferencesAtPosition(filename: String, offset: number): LspReferenceData[] {
    let lspDriverHelper = new LspDriverHelper()
    let filePath = path.resolve(filename.valueOf())
    let arktsconfig = this.fileNameToArktsconfig[filePath]
    let ets2pandaCmd = ['-', '--extension', 'ets', '--arktsconfig', arktsconfig]
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath)
    const source = fs.readFileSync(filePath, 'utf8').toString().replace(/\r\n/g, '\n');
    let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg)
    PluginDriver.getInstance().getPluginContext().setArkTSProgram(localCtx.program)
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED)
    let ast = EtsScript.fromContext(localCtx)
    PluginDriver.getInstance().getPluginContext().setArkTSAst(ast)
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED)
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED)
    let declInfo = global.es2panda._getDeclInfo(localCtx.peer, offset)
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN)
    lspDriverHelper.destroyContext(localCtx)
    lspDriverHelper.destroyConfig(localCfg)
    let result: LspReferenceData[] = []
    let moduleName = path.basename(path.dirname(arktsconfig))
    let buildConfig: BuildConfig = this.moduleToBuildConfig[moduleName]
    for (let i = 0; i < buildConfig.compileFiles.length; i++) {
      let filePath = path.resolve(buildConfig.compileFiles[i])
      let arktsconfig = this.fileNameToArktsconfig[filePath]
      let ets2pandaCmd = ['-', '--extension', 'ets', '--arktsconfig', arktsconfig]
      let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath)
      const source = fs.readFileSync(filePath, 'utf8').toString().replace(/\r\n/g, '\n');
      let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg)
      PluginDriver.getInstance().getPluginContext().setArkTSProgram(localCtx.program)
      lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED)
      let ast = EtsScript.fromContext(localCtx)
      PluginDriver.getInstance().getPluginContext().setArkTSAst(ast)
      PluginDriver.getInstance().runPluginHook(PluginHook.PARSED)
      lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED)
      let ptr = global.es2panda._getReferencesAtPosition(localCtx.peer, declInfo)
      PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN)
      lspDriverHelper.destroyContext(localCtx)
      lspDriverHelper.destroyConfig(localCfg)
      let refs = new LspReferences(ptr)
      result.push(...refs.referenceInfos)
    }
    return Array.from(new Set(result));
  }

  getSyntacticDiagnostics(filename: String): LspDiagsNode {
    let lspDriverHelper = new LspDriverHelper()
    let filePath = path.resolve(filename.valueOf())
    let arktsconfig = this.fileNameToArktsconfig[filePath]
    let ets2pandaCmd = ['-', '--extension', 'ets', '--arktsconfig', arktsconfig]
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath)
    const source = fs.readFileSync(filePath, 'utf8').toString().replace(/\r\n/g, '\n');
    let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg)
    PluginDriver.getInstance().getPluginContext().setArkTSProgram(localCtx.program)
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED)
    let ast = EtsScript.fromContext(localCtx)
    PluginDriver.getInstance().getPluginContext().setArkTSAst(ast)
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED)
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED)
    let ptr = global.es2panda._getSyntacticDiagnostics(localCtx.peer)
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN)
    lspDriverHelper.destroyContext(localCtx)
    lspDriverHelper.destroyConfig(localCfg)
    return new LspDiagsNode(ptr)
  }

  getSuggestionDiagnostics(filename: String): LspDiagsNode {
    let lspDriverHelper = new LspDriverHelper()
    let filePath = path.resolve(filename.valueOf())
    let arktsconfig = this.fileNameToArktsconfig[filePath]
    let ets2pandaCmd = ['-', '--extension', 'ets', '--arktsconfig', arktsconfig]
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath)
    const source = fs.readFileSync(filePath, 'utf8').toString().replace(/\r\n/g, '\n');
    let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg)
    PluginDriver.getInstance().getPluginContext().setArkTSProgram(localCtx.program)
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED)
    let ast = EtsScript.fromContext(localCtx)
    PluginDriver.getInstance().getPluginContext().setArkTSAst(ast)
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED)
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED)
    let ptr = global.es2panda._getSuggestionDiagnostics(localCtx.peer)
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN)
    lspDriverHelper.destroyContext(localCtx)
    lspDriverHelper.destroyConfig(localCfg)
    return new LspDiagsNode(ptr)
  }

  getQuickInfoAtPosition(filename: String, offset: number): LspQuickInfo {
    let lspDriverHelper = new LspDriverHelper()
    let filePath = path.resolve(filename.valueOf())
    let arktsconfig = this.fileNameToArktsconfig[filePath]
    let ets2pandaCmd = ['-', '--extension', 'ets', '--arktsconfig', arktsconfig]
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath)
    const source = fs.readFileSync(filePath, 'utf8').toString().replace(/\r\n/g, '\n');
    let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg)
    PluginDriver.getInstance().getPluginContext().setArkTSProgram(localCtx.program)
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED)
    let ast = EtsScript.fromContext(localCtx)
    PluginDriver.getInstance().getPluginContext().setArkTSAst(ast)
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED)
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED)
    let ptr = global.es2panda._getQuickInfoAtPosition(filename, localCtx.peer, offset)
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN)
    lspDriverHelper.destroyContext(localCtx)
    lspDriverHelper.destroyConfig(localCfg)
    return new LspQuickInfo(ptr)
  }

  getDocumentHighlights(filename: String, offset: number): LspDocumentHighlightsReferences {
    let lspDriverHelper = new LspDriverHelper()
    let filePath = path.resolve(filename.valueOf())
    let arktsconfig = this.fileNameToArktsconfig[filePath]
    let ets2pandaCmd = ['-', '--extension', 'ets', '--arktsconfig', arktsconfig]
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath)
    const source = fs.readFileSync(filePath, 'utf8').toString().replace(/\r\n/g, '\n');
    let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg)
    PluginDriver.getInstance().getPluginContext().setArkTSProgram(localCtx.program)
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED)
    let ast = EtsScript.fromContext(localCtx)
    PluginDriver.getInstance().getPluginContext().setArkTSAst(ast)
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED)
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED)
    let ptr = global.es2panda._getDocumentHighlights(localCtx.peer, offset)
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN)
    lspDriverHelper.destroyContext(localCtx)
    lspDriverHelper.destroyConfig(localCfg)
    return new LspDocumentHighlightsReferences(ptr)
  }

  getCompletionAtPosition(filename: String, offset: number): LspCompletionInfo {
    let lspDriverHelper = new LspDriverHelper()
    let filePath = path.resolve(filename.valueOf())
    let arktsconfig = this.fileNameToArktsconfig[filePath]
    let ets2pandaCmd = ['-', '--extension', 'ets', '--arktsconfig', arktsconfig]
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath)
    const source = fs.readFileSync(filePath, 'utf8').toString().replace(/\r\n/g, '\n');
    let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg)
    PluginDriver.getInstance().getPluginContext().setArkTSProgram(localCtx.program)
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED)
    let ast = EtsScript.fromContext(localCtx)
    PluginDriver.getInstance().getPluginContext().setArkTSAst(ast)
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED)
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED)
    let ptr = global.es2panda._getCompletionAtPosition(localCtx.peer, offset)
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN)
    lspDriverHelper.destroyContext(localCtx)
    lspDriverHelper.destroyConfig(localCfg)
    return new LspCompletionInfo(ptr)
  }

  toLineColumnOffset(filename: String, offset: number): LspLineAndCharacter {
    let lspDriverHelper = new LspDriverHelper()
    let filePath = path.resolve(filename.valueOf())
    let arktsconfig = this.fileNameToArktsconfig[filePath]
    let ets2pandaCmd = ['-', '--extension', 'ets', '--arktsconfig', arktsconfig]
    let localCfg = lspDriverHelper.createCfg(ets2pandaCmd, filePath)
    const source = fs.readFileSync(filePath, 'utf8').toString().replace(/\r\n/g, '\n');
    let localCtx = lspDriverHelper.createCtx(source, filePath, localCfg)
    PluginDriver.getInstance().getPluginContext().setArkTSProgram(localCtx.program)
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_PARSED)
    let ast = EtsScript.fromContext(localCtx)
    PluginDriver.getInstance().getPluginContext().setArkTSAst(ast)
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED)
    lspDriverHelper.proceedToState(localCtx, Es2pandaContextState.ES2PANDA_STATE_CHECKED)
    let ptr = global.es2panda._toLineColumnOffset(localCtx.peer, offset)
    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN)
    lspDriverHelper.destroyContext(localCtx)
    lspDriverHelper.destroyConfig(localCfg)
    return new LspLineAndCharacter(ptr)
  }
}
