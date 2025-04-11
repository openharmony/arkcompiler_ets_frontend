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

import { ABC_SUFFIX, ARKTSCONFIG_JSON_FILE, LANGUAGE_VERSION } from '../preDefine';
import { changeFileExtension } from '../utils';
import { BuildConfig, DependentModuleConfig, ModuleInfo, CompileFileInfo } from '../types';
import { ArkTSConfigGenerator } from './generateArkTSConfig';

export class BuildMode {
  buildConfig: BuildConfig;
  entryFiles: Set<string>;
  compileFiles: Map<string, CompileFileInfo>;
  cacheDir: string;
  pandaSdkPath: string;
  buildSdkPath: string;
  packageName: string;
  sourceRoots: string[];
  moduleRootPath: string;
  moduleType: string;
  dependentModuleList: DependentModuleConfig[];
  moduleInfos: Map<string, ModuleInfo>;
  declgenV1OutPath: string | undefined;
  declgenBridgeCodePath: string | undefined;
  hasMainModule: boolean;

  constructor(buildConfig: BuildConfig) {
    this.buildConfig = buildConfig;
    this.entryFiles = new Set<string>(buildConfig.compileFiles as string[]);
    this.cacheDir = buildConfig.cachePath as string;
    this.pandaSdkPath = buildConfig.pandaSdkPath as string;
    this.buildSdkPath = buildConfig.buildSdkPath as string;
    this.packageName = buildConfig.packageName as string;
    this.sourceRoots = buildConfig.sourceRoots as string[];
    this.moduleRootPath = buildConfig.moduleRootPath as string;
    this.moduleType = buildConfig.moduleType as string;
    this.dependentModuleList = buildConfig.dependentModuleList;
    this.hasMainModule = buildConfig.hasMainModule;

    this.declgenV1OutPath = buildConfig.declgenV1OutPath as string | undefined;
    this.declgenBridgeCodePath = buildConfig.declgenBridgeCodePath as string | undefined;

    this.moduleInfos = new Map<string, ModuleInfo>();
    this.compileFiles = new Map<string, CompileFileInfo>();
  }

  private getDependentModules(moduleInfo: ModuleInfo): Map<string, ModuleInfo>[] {
    let dynamicDepModules: Map<string, ModuleInfo> = new Map<string, ModuleInfo>();
    let staticDepModules: Map<string, ModuleInfo> = new Map<string, ModuleInfo>();

    if (moduleInfo.isMainModule) {
      this.moduleInfos.forEach((module: ModuleInfo, packageName: string) => {
        if (module.isMainModule) {
          return;
        }
        module.language === LANGUAGE_VERSION.ARKTS_1_2
          ? staticDepModules.set(packageName, module)
          : dynamicDepModules.set(packageName, module);
      });
      return [dynamicDepModules, staticDepModules];
    }

    if (moduleInfo.dependencies) {
      moduleInfo.dependencies.forEach((packageName: string) => {
        let depModuleInfo: ModuleInfo | undefined = this.moduleInfos.get(packageName);
        if (!depModuleInfo) {
          console.error(`Module ${packageName} not found in moduleInfos`);
        } else {
          depModuleInfo.language === LANGUAGE_VERSION.ARKTS_1_2
            ? staticDepModules.set(packageName, depModuleInfo)
            : dynamicDepModules.set(packageName, depModuleInfo);
        }
      });
    }
    return [dynamicDepModules, staticDepModules];
  }

  private generateArkTSConfigForModules(compileFileInfos: Record<string, string>): void {
    let generator = ArkTSConfigGenerator.getGenerator(this.buildConfig, this.moduleInfos);
    this.moduleInfos.forEach((moduleInfo: ModuleInfo, moduleRootPath: string) => {
      for (const fileInfo of moduleInfo.compileFileInfos) {
        compileFileInfos[fileInfo.filePath] = fileInfo.arktsConfigFile;
      }
      generator.writeArkTSConfigFile(moduleInfo);
    });
  }

  private collectDepModuleInfos(): void {
    this.moduleInfos.forEach((moduleInfo) => {
      let [dynamicDepModules, staticDepModules] = this.getDependentModules(moduleInfo);
      moduleInfo.dynamicDepModuleInfos = dynamicDepModules;
      moduleInfo.staticDepModuleInfos = staticDepModules;
    });
  }

  private collectModuleInfos(): void {
    if (this.hasMainModule && (!this.packageName || !this.moduleRootPath || !this.sourceRoots)) {
      console.error('Main module info from hvigor is not correct.');
    }
    let mainModuleInfo: ModuleInfo = {
      isMainModule: this.hasMainModule,
      packageName: this.packageName,
      moduleRootPath: this.moduleRootPath,
      moduleType: this.moduleType,
      sourceRoots: this.sourceRoots,
      entryFile: '',
      arktsConfigFile: path.resolve(this.cacheDir, this.packageName, ARKTSCONFIG_JSON_FILE),
      dynamicDepModuleInfos: new Map<string, ModuleInfo>(),
      staticDepModuleInfos: new Map<string, ModuleInfo>(),
      compileFileInfos: [],
      declgenV1OutPath: this.declgenV1OutPath,
      declgenBridgeCodePath: this.declgenBridgeCodePath
    };
    this.moduleInfos.set(this.packageName, mainModuleInfo);
    this.dependentModuleList.forEach((module: DependentModuleConfig) => {
      if (!module.packageName || !module.modulePath || !module.sourceRoots || !module.entryFile) {
        console.error('Dependent module info from hvigor is not correct.');
      }
      let moduleInfo: ModuleInfo = {
        isMainModule: false,
        packageName: module.packageName,
        moduleRootPath: module.modulePath,
        moduleType: module.moduleType,
        sourceRoots: module.sourceRoots,
        entryFile: module.entryFile,
        arktsConfigFile: path.resolve(this.cacheDir, module.packageName, ARKTSCONFIG_JSON_FILE),
        compileFileInfos: [],
        dynamicDepModuleInfos: new Map<string, ModuleInfo>(),
        staticDepModuleInfos: new Map<string, ModuleInfo>(),
        declgenV1OutPath: undefined,
        declgenBridgeCodePath: undefined,
        language: module.language,
        declFilesPath: module.declFilesPath,
        dependencies: module.dependencies
      };
      this.moduleInfos.set(module.packageName, moduleInfo);
    });
    this.collectDepModuleInfos();
  }

  private collectCompileFiles(): void {
    this.entryFiles.forEach((file: string) => {
      for (const [packageName, moduleInfo] of this.moduleInfos) {
        if (!file.startsWith(moduleInfo.moduleRootPath)) {
          continue;
        }
        let filePathFromModuleRoot: string = path.relative(moduleInfo.moduleRootPath, file);
        let filePathInCache: string = path.join(this.cacheDir, moduleInfo.packageName, filePathFromModuleRoot);
        let abcFilePath: string = path.resolve(changeFileExtension(filePathInCache, ABC_SUFFIX));

        let fileInfo: CompileFileInfo = {
          filePath: file,
          dependentFiles: [],
          abcFilePath: abcFilePath,
          arktsConfigFile: moduleInfo.arktsConfigFile,
          packageName: moduleInfo.packageName
        };
        moduleInfo.compileFileInfos.push(fileInfo);
        this.compileFiles.set(file, fileInfo);
        return;
      }
      console.error('File does not belong to any module in moduleInfos.');
    });
  }

  public generateModuleInfos(): void {
    this.collectModuleInfos();
    this.collectCompileFiles();
  }

  public async generateArkTSConfig(compileFileInfos: Record<string, string>): Promise<void> {
    this.generateModuleInfos();
    this.generateArkTSConfigForModules(compileFileInfos);
  }
}
