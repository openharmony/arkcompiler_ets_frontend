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

import * as os from 'os';
import * as path from 'path';
import * as fs from 'fs';
import * as child_process from 'child_process';

// @ts-ignore
import { arkts, arktsGlobal } from 'libarkts/arkoala-arkts/libarkts/build/src/es2panda';

import {
  ABC_SUFFIX,
  ARKTSCONFIG_JSON_FILE,
  BUILD_MODE,
  LINKER_INPUT_FILE,
  MERGED_ABC_FILE,
  SYSTEM_SDK_PATH_FROM_SDK,
} from '../pre_define';
import {
  changeFileExtension,
  ensurePathExists
} from '../utils';
import { BuildConfigType } from '../init/process_build_config';
import {
  PluginDriver,
  PluginHook
} from '../plugins/plugins_driver';
import {
  Logger,
  LogData,
  LogDataFactory
} from '../logger'
import { ErrorCode } from '../error_code'

interface ArkTSConfigObject {
  compilerOptions: {
    package: string,
    baseUrl: string,
    paths: Record<string, string[]>;
    dependencies: string[] | undefined;
    entry: string;
  }
};

interface CompileFileInfo {
  filePath: string,
  dependentFiles: string[],
  abcFilePath: string,
  arktsConfigFile: string
};

interface ModuleInfo {
  isMainModule: boolean,
  packageName: string,
  moduleRootPath: string,
  sourceRoots: string[],
  entryFile: string,
  arktsConfigFile: string,
  compileFileInfos: CompileFileInfo[],
  dependencies?: string[]
}

interface DependentModule {
  packageName: string,
  moduleName: string,
  moduleType: string,
  modulePath: string,
  sourceRoots: string[],
  entryFile: string
}

export abstract class BaseMode {
  buildConfig: Record<string, BuildConfigType>;
  entryFiles: Set<string>;
  outputDir: string;
  cacheDir: string;
  pandaSdkPath: string;
  buildSdkPath: string;
  packageName: string;
  sourceRoots: string[];
  moduleRootPath: string;
  dependentModuleList: DependentModule[];
  moduleInfos: Map<string, ModuleInfo>;
  mergedAbcFile: string;
  abcLinkerCmd: string[];
  logger: Logger;
  isDebug: boolean;

  constructor(buildConfig: Record<string, BuildConfigType>) {
    this.buildConfig = buildConfig;
    this.entryFiles = new Set<string>(buildConfig.compileFiles as string[]);
    this.outputDir = buildConfig.loaderOutPath as string;
    this.cacheDir = buildConfig.cachePath as string;
    this.pandaSdkPath = buildConfig.pandaSdkPath as string;
    this.buildSdkPath = buildConfig.buildSdkPath as string;
    this.packageName = buildConfig.packageName as string;
    this.sourceRoots = buildConfig.sourceRoots as string[];
    this.moduleRootPath = buildConfig.moduleRootPath as string;
    this.dependentModuleList = buildConfig.dependentModuleList as DependentModule[];
    this.isDebug = buildConfig.buildMode as string === BUILD_MODE.DEBUG;

    this.moduleInfos = new Map<string, ModuleInfo>();
    this.mergedAbcFile = path.resolve(this.outputDir, MERGED_ABC_FILE);
    this.abcLinkerCmd = ['"' + this.buildConfig.abcLinkerPath + '"'];

    this.logger = Logger.getInstance();
  }

  public compile(fileInfo: CompileFileInfo): void {
    ensurePathExists(fileInfo.abcFilePath);

    let ets2pandaCmd: string[] = [
      '_',
      '--extension',
      'sts',
      '--arktsconfig',
      fileInfo.arktsConfigFile,
      '--output',
      fileInfo.abcFilePath,
    ];

    if (this.isDebug) {
      ets2pandaCmd.push('--debug-info');
    }
    ets2pandaCmd.push(fileInfo.filePath);
    this.logger.printInfo('ets2pandaCmd: ' + ets2pandaCmd.join(' '));
    try {
      arktsGlobal.config = arkts.createConfig(ets2pandaCmd);
      const source = fs.readFileSync(fileInfo.filePath).toString();
      arktsGlobal.context = arkts.createContextFromString(arktsGlobal.config, source, fileInfo.filePath);

      arkts.proceedToState(arkts.Es2pandaContextState.ES2PANDA_STATE_PARSED);
      this.logger.printInfo('parsed');
      PluginDriver.getInstance().runPluginHook(PluginHook.PARSED);

      arkts.proceedToState(arkts.Es2pandaContextState.ES2PANDA_STATE_CHECKED);
      PluginDriver.getInstance().runPluginHook(PluginHook.CHECKED);

      arkts.proceedToState(arkts.Es2pandaContextState.ES2PANDA_STATE_BIN_GENERATED);
      this.logger.printInfo('bin generated');
    } catch (error) {
      if (error instanceof Error) {
        const logData: LogData = LogDataFactory.newInstance(
          ErrorCode.BUILDSYSTEM_COMPILE_ABC_FAIL,
          'Compile abc files failed.',
          error.message
        );
        this.logger.printError(logData);
      }
    } finally {
      PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN);
      arkts.destroyConfig(arktsGlobal.config);
    }
  }

  public mergeAbcFiles(): void {
    let linkerInputFile: string = path.join(this.cacheDir, LINKER_INPUT_FILE);
    let linkerInputContent: string = '';
    this.moduleInfos.forEach((moduleInfo) => {
      moduleInfo.compileFileInfos.forEach((fileInfo) => {
        linkerInputContent += fileInfo.abcFilePath + os.EOL;
      });
    });
    fs.writeFileSync(linkerInputFile, linkerInputContent);

    this.abcLinkerCmd.push('--output');
    this.abcLinkerCmd.push('"' + this.mergedAbcFile + '"');
    this.abcLinkerCmd.push('--');
    this.abcLinkerCmd.push('@' + '"' + linkerInputFile + '"');

    let abcLinkerCmdStr: string = this.abcLinkerCmd.join(' ');
    this.logger.printInfo(abcLinkerCmdStr);

    ensurePathExists(this.mergedAbcFile);
    try {
      child_process.execSync(abcLinkerCmdStr).toString();
    } catch(error) {
      if (error instanceof Error) {
        const logData: LogData = LogDataFactory.newInstance(
          ErrorCode.BUILDSYSTEM_LINK_ABC_FAIL,
          'Link abc files failed.',
          error.message
        );
        this.logger.printError(logData);
      }
    }
  }

  private generateSystemSdkPathSection(pathSection: Record<string, string[]>): void {
    let systemSdkPath: string = path.resolve(this.buildSdkPath, SYSTEM_SDK_PATH_FROM_SDK);
    function traverse(currentDir: string) {
      const items = fs.readdirSync(currentDir);
      for (const item of items) {
        const itemPath = path.join(currentDir, item);
        const stat = fs.statSync(itemPath);

        if (stat.isFile()) {
          const basename = path.basename(item, '.d.ets');
          pathSection[basename] = [changeFileExtension(itemPath, '', '.d.ets')];
        }
      }
    }
    let apiPath: string = path.resolve(systemSdkPath, 'api');
    let arktsPath: string = path.resolve(systemSdkPath, 'arkts');
    let kitsPath: string = path.resolve(systemSdkPath, 'kits');
    if (!fs.existsSync(apiPath) || !fs.existsSync(arktsPath) || !fs.existsSync(kitsPath)) {
      const logData: LogData = LogDataFactory.newInstance(
        ErrorCode.BUILDSYSTEM_SDK_NOT_EXIST_FAIL,
        `sdk path ${apiPath} or ${arktsPath} or ${kitsPath} not exist.`
      );
      this.logger.printErrorAndExit(logData);
    }
    traverse(apiPath);
    traverse(arktsPath);
    traverse(kitsPath);
  }

  private getDependentModules(moduleInfo: ModuleInfo): Map<string, ModuleInfo> {
    if (moduleInfo.isMainModule) {
      return this.moduleInfos;
    }

    let depModules: Map<string, ModuleInfo> = new Map<string, ModuleInfo>();
    if (moduleInfo.dependencies) {
      moduleInfo.dependencies.forEach((packageName: string) => {
        let depModuleInfo: ModuleInfo | undefined = this.moduleInfos.get(packageName);
        if (!depModuleInfo) {
          const logData: LogData = LogDataFactory.newInstance(
            ErrorCode.BUILDSYSTEM_DEPENDENT_MODULE_INFO_NOT_FOUND,
            `Module ${packageName} not found in moduleInfos`
          );
          this.logger.printErrorAndExit(logData);
        } else {
          depModules.set(packageName, depModuleInfo);
        }
      });
    }
    return depModules;
  }

  private generateDependenciesSection(moduleInfo: ModuleInfo, dependenciesSection: string[]): void {
    let depModules: Map<string, ModuleInfo> = this.getDependentModules(moduleInfo);
    depModules.forEach((depModuleInfo: ModuleInfo) => {
      if (depModuleInfo.isMainModule) {
        return;
      }
      dependenciesSection.push(depModuleInfo.arktsConfigFile);
    });
  }

  private writeArkTSConfigFile(moduleInfo: ModuleInfo, pathSection: Record<string, string[]>,
    dependenciesSection: string[]): void {
    if (!moduleInfo.sourceRoots || moduleInfo.sourceRoots.length == 0) {
      const logData: LogData = LogDataFactory.newInstance(
        ErrorCode.BUILDSYSTEM_SOURCEROOTS_NOT_SET_FAIL,
        'SourceRoots not set from hvigor.'
      );
      this.logger.printErrorAndExit(logData);
    }

    let baseUrl: string = path.resolve(moduleInfo.moduleRootPath, moduleInfo.sourceRoots[0]);
    pathSection[moduleInfo.packageName] = [baseUrl];
    let arktsConfig: ArkTSConfigObject = {
      compilerOptions: {
        package: moduleInfo.packageName,
        baseUrl: baseUrl,
        paths: pathSection,
        dependencies: dependenciesSection.length === 0 ? undefined : dependenciesSection,
        entry: moduleInfo.entryFile
      }
    };

    ensurePathExists(moduleInfo.arktsConfigFile);
    fs.writeFileSync(moduleInfo.arktsConfigFile, JSON.stringify(arktsConfig, null, 2), 'utf-8');
  }

  private generateArkTSConfigForModules(): void {
    let pathSection: Record<string, string[]> = {};
    pathSection['std'] = [path.resolve(this.pandaSdkPath, 'lib', 'stdlib', 'std')];
    pathSection['escompat'] = [path.resolve(this.pandaSdkPath, 'lib', 'stdlib', 'escompat')];
    this.generateSystemSdkPathSection(pathSection);

    this.moduleInfos.forEach((moduleInfo: ModuleInfo, moduleRootPath: string) => {
      pathSection[moduleInfo.packageName] = [
        path.resolve(moduleRootPath, moduleInfo.sourceRoots[0])
      ]
    });

    this.moduleInfos.forEach((moduleInfo: ModuleInfo, moduleRootPath: string)=> {
      let dependenciesSection: string[] = [];
      this.generateDependenciesSection(moduleInfo, dependenciesSection);
      this.writeArkTSConfigFile(moduleInfo, pathSection, dependenciesSection);
    });
  }

  private generateModuleInfos(): void {
    if (!this.packageName || !this.moduleRootPath || !this.sourceRoots) { // BUILDSYSTEM_MODULE_INFO_NOT_CORRECT_FAIL
      const logData: LogData = LogDataFactory.newInstance(
        ErrorCode.BUILDSYSTEM_MODULE_INFO_NOT_CORRECT_FAIL,
        'Main module info from hvigor is not correct.'
      );
      this.logger.printError(logData);
    }
    let mainModuleInfo: ModuleInfo = {
      isMainModule: true,
      packageName: this.packageName,
      moduleRootPath: this.moduleRootPath,
      sourceRoots: this.sourceRoots,
      entryFile: '',
      arktsConfigFile: path.resolve(this.cacheDir, this.packageName, ARKTSCONFIG_JSON_FILE),
      compileFileInfos: []
    }
    this.moduleInfos.set(this.moduleRootPath, mainModuleInfo);
    this.dependentModuleList.forEach((module: DependentModule) => {
      if (!module.packageName || !module.modulePath || !module.sourceRoots || !module.entryFile) {
        const logData: LogData = LogDataFactory.newInstance(
          ErrorCode.BUILDSYSTEM_DEPENDENT_MODULE_INFO_NOT_CORRECT_FAIL,
          'Dependent module info from hvigor is not correct.'
        );
        this.logger.printError(logData);
      }
      let moduleInfo: ModuleInfo = {
        isMainModule: false,
        packageName: module.packageName,
        moduleRootPath: module.modulePath,
        sourceRoots: module.sourceRoots,
        entryFile: module.entryFile,
        arktsConfigFile: path.resolve(this.cacheDir, module.packageName, ARKTSCONFIG_JSON_FILE),
        compileFileInfos: []
      }
      this.moduleInfos.set(module.modulePath, moduleInfo);
    });

    this.entryFiles.forEach((file: string) => {
      for (const [modulePath, moduleInfo] of this.moduleInfos) {
        if (file.startsWith(modulePath)) {
          let filePathFromModuleRoot: string = path.relative(modulePath, file);
          let filePathInCache: string = path.join(this.cacheDir, moduleInfo.packageName, filePathFromModuleRoot);
          let abcFilePath: string = path.resolve(changeFileExtension(filePathInCache, ABC_SUFFIX));

          let fileInfo: CompileFileInfo = {
            filePath: file,
            dependentFiles: [],
            abcFilePath: abcFilePath,
            arktsConfigFile: moduleInfo.arktsConfigFile
          };
          moduleInfo.compileFileInfos.push(fileInfo);
          return;
        }
      }
      const logData: LogData = LogDataFactory.newInstance(
        ErrorCode.BUILDSYSTEM_FILE_NOT_BELONG_TO_ANY_MODULE_FAIL,
        'File does not belong to any module in moduleInfos.',
        '',
        file
      );
      this.logger.printError(logData);
    });
  }

  public async run(): Promise<void> {
    this.generateModuleInfos();
    this.generateArkTSConfigForModules();

    const compilePromises: Promise<void>[] = [];
    this.moduleInfos.forEach((moduleInfo) => {
      moduleInfo.compileFileInfos.forEach((fileInfo) => {
        compilePromises.push(new Promise<void>((resolve) => {
          this.compile(fileInfo);
          resolve();
        }));
      });
    });
    await Promise.all(compilePromises);

    this.mergeAbcFiles();
  }
}
