/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import * as path from 'path';
import * as fs from 'fs';

import { arkts, arktsGlobal } from 'libarkts/arkoala-arkts/libarkts/build/src/es2panda';

import {
  ABC_SUFFIX,
  ARKTSCONFIG_JSON_FILE,
  MERGED_ABC_FILE
} from '../pre_define';
import { changeFileExtension } from '../utils';
import { BuildConfigType } from '../init/process_build_config';
import {
  PluginDriver,
  PluginHook
} from '../plugins/plugins_driver';

interface ArkTSConfigObject {
  compilerOptions: {
    baseUrl: string,
    paths: Record<string, string[]>;
  }
};

interface CompileFileInfo {
  filePath: string,
  dependentFiles: string[],
  outputPath: string
};

export abstract class BaseMode {
  buildConfig: Record<string, BuildConfigType>;
  entryFiles: Set<string>;
  compileFiles: Map<string, CompileFileInfo>;
  outputDir: string;
  arktsConfigJsonFile: string;
  mergedAbcFile: string;
  depAnalzerCmd: string[];
  abcLinkerCmd: string[];

  constructor(buildConfig: Record<string, BuildConfigType>) {
    this.buildConfig = buildConfig;
    this.entryFiles = new Set<string>(buildConfig.entryFiles);
    this.compileFiles = new Map<string, CompileFileInfo>;
    this.outputDir = buildConfig.outputDir as string;
    this.arktsConfigJsonFile = path.resolve(this.outputDir, ARKTSCONFIG_JSON_FILE);
    this.mergedAbcFile = path.resolve(this.outputDir, MERGED_ABC_FILE);
    this.depAnalzerCmd = ['"' + this.buildConfig.depAnalyzerPath + '"'];
    this.abcLinkerCmd = ['"' + this.buildConfig.abcLinkerPath + '"'];
  }

  public generateArkTSCompileConfig(dependentFiles: string[]): void {
    let es2pandLibPath = path.resolve(
      __dirname, '..', '..', 'node_modules', 'libarkts', 'arkoala-arkts', 'node_modules', '@panda', 'sdk', 'ets');
    let arktsConfig: ArkTSConfigObject = {
      compilerOptions: {
        baseUrl: path.resolve(__dirname, '..', '..'),
        paths: {
          'std': [path.resolve(es2pandLibPath, 'stdlib', 'std')],
          'escompat': [path.resolve(es2pandLibPath, 'stdlib', 'escompat')]
        }
      }
    };

    dependentFiles.forEach(file => {
      arktsConfig.compilerOptions.paths[path.basename(file)] = [file];
    });

    fs.writeFileSync(this.arktsConfigJsonFile, JSON.stringify(arktsConfig, null, 2), 'utf-8');
  }

  public compile(fileInfo: CompileFileInfo): void {
    // call ets2panda
    const source = fs.readFileSync(fileInfo.filePath, 'utf8');
    arktsGlobal.config = arkts.createConfig([
        '_',
        '--arktsconfig',
        this.arktsConfigJsonFile,
        '--output',
        fileInfo.outputPath,
        fileInfo.filePath
    ]);
    arktsGlobal.context = arkts.createContextFromString(arktsGlobal.config, source, fileInfo.filePath);

    arkts.proceedToState(arkts.Es2pandaContextState.ES2PANDA_STATE_PARSED);
    console.log('parsed');

    let ast: object = arkts.unpackNode(arkts.getAstFromContext()) as object;
    console.log(ast);

    PluginDriver.getInstance().getPluginContext().setArkTSAst(ast);
    PluginDriver.getInstance().runPluginHook(PluginHook.PARSED);

    arkts.proceedToState(arkts.Es2pandaContextState.ES2PANDA_STATE_CHECKED);
    PluginDriver.getInstance().runPluginHook(PluginHook.CHECKED);

    arkts.proceedToState(arkts.Es2pandaContextState.ES2PANDA_STATE_BIN_GENERATED);
    console.log('bin generated');

    PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN);
  }

  public mergeAbcFiles(): void {
    // call static linker
  }

  public run(): void {
    this.collectCompileFiles();

    this.compileFiles.forEach((fileInfo: CompileFileInfo, file: string) => {
      this.generateArkTSCompileConfig(fileInfo.dependentFiles);
      this.compile(fileInfo);
    });

    this.mergeAbcFiles();
  }

  private collectCompileFiles(): void {
    // TODO: get dependent file from depAnalyzer
    this.entryFiles.forEach(file => {
      let fileInfo: CompileFileInfo = {
        filePath: file,
        dependentFiles: [],
        outputPath: changeFileExtension(path.resolve(this.outputDir, file), ABC_SUFFIX)
      };
      this.compileFiles.set(file, fileInfo);
    });
  }
}