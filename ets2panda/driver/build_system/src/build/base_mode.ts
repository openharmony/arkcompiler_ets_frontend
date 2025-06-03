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
import * as crypto from 'crypto';


import cluster, {
  Cluster,
  Worker,
} from 'cluster';
import {
  Worker as ThreadWorker,
  workerData
} from 'worker_threads';
import {
  ABC_SUFFIX,
  ARKTSCONFIG_JSON_FILE,
  BUILD_MODE,
  DEFAULT_WOKER_NUMS,
  DECL_ETS_SUFFIX,
  DEPENDENCY_JSON_FILE,
  LANGUAGE_VERSION,
  LINKER_INPUT_FILE,
  MERGED_ABC_FILE,
  TS_SUFFIX,
  DEPENDENCY_INPUT_FILE,
  PROJECT_BUILD_CONFIG_FILE
} from '../pre_define';
import {
  changeDeclgenFileExtension,
  changeFileExtension,
  ensurePathExists,
  getFileHash,
  isMac
} from '../utils';
import {
  PluginDriver,
  PluginHook
} from '../plugins/plugins_driver';
import {
  Logger,
  LogData,
  LogDataFactory
} from '../logger';
import { ErrorCode } from '../error_code';
import {
  ArkTS,
  ArkTSGlobal,
  BuildConfig,
  CompileFileInfo,
  DependencyFileConfig,
  DependentModuleConfig,
  JobInfo,
  KPointer,
  ModuleInfo
} from '../types';
import { ArkTSConfigGenerator } from './generate_arktsconfig';
import { SetupClusterOptions } from '../types';
import { create } from 'domain';
import { emitKeypressEvents } from 'readline';
export abstract class BaseMode {
  buildConfig: BuildConfig;
  entryFiles: Set<string>;
  allFiles: Map<string, CompileFileInfo>;
  compileFiles: Map<string, CompileFileInfo>;
  outputDir: string;
  cacheDir: string;
  pandaSdkPath: string;
  buildSdkPath: string;
  packageName: string;
  sourceRoots: string[];
  moduleRootPath: string;
  moduleType: string;
  dependentModuleList: DependentModuleConfig[];
  moduleInfos: Map<string, ModuleInfo>;
  mergedAbcFile: string;
  dependencyJsonFile: string;
  abcLinkerCmd: string[];
  dependencyAnalyzerCmd: string[];
  logger: Logger;
  isDebug: boolean;
  enableDeclgenEts2Ts: boolean;
  declgenV1OutPath: string | undefined;
  declgenBridgeCodePath: string | undefined;
  hasMainModule: boolean;
  abcFiles: Set<string>;
  hashCache: Record<string, string>;
  hashCacheFile: string;
  isCacheFileExists: boolean;
  dependencyFileMap: DependencyFileConfig | null;
  isBuildConfigModified: boolean | undefined;
  hasCleanWorker: boolean;

  constructor(buildConfig: BuildConfig) {
    this.buildConfig = buildConfig;
    this.entryFiles = new Set<string>(buildConfig.compileFiles as string[]);
    this.outputDir = buildConfig.loaderOutPath as string;
    this.cacheDir = buildConfig.cachePath as string;
    this.pandaSdkPath = buildConfig.pandaSdkPath as string;
    this.buildSdkPath = buildConfig.buildSdkPath as string;
    this.packageName = buildConfig.packageName as string;
    this.sourceRoots = buildConfig.sourceRoots as string[];
    this.moduleRootPath = buildConfig.moduleRootPath as string;
    this.moduleType = buildConfig.moduleType as string;
    this.dependentModuleList = buildConfig.dependentModuleList;
    this.isDebug = buildConfig.buildMode as string === BUILD_MODE.DEBUG;
    this.hasMainModule = buildConfig.hasMainModule;
    this.abcFiles = new Set<string>();
    this.hashCacheFile = path.join(this.cacheDir, 'hash_cache.json');
    this.hashCache = this.loadHashCache();
    this.isCacheFileExists = fs.existsSync(this.hashCacheFile);
    this.dependencyFileMap = null;
    this.isBuildConfigModified = buildConfig.isBuildConfigModified as boolean | undefined;

    this.enableDeclgenEts2Ts = buildConfig.enableDeclgenEts2Ts as boolean;
    this.declgenV1OutPath = buildConfig.declgenV1OutPath as string | undefined;
    this.declgenBridgeCodePath = buildConfig.declgenBridgeCodePath as string | undefined;

    this.moduleInfos = new Map<string, ModuleInfo>();
    this.compileFiles = new Map<string, CompileFileInfo>();
    this.allFiles = new Map<string, CompileFileInfo>();
    this.mergedAbcFile = path.resolve(this.outputDir, MERGED_ABC_FILE);
    this.dependencyJsonFile = path.resolve(this.cacheDir, DEPENDENCY_JSON_FILE);
    this.abcLinkerCmd = ['"' + this.buildConfig.abcLinkerPath + '"'];
    this.dependencyAnalyzerCmd = ['"' + this.buildConfig.dependencyAnalyzerPath + '"'];

    this.logger = Logger.getInstance();
    this.hasCleanWorker = false;
  }

  public declgen(fileInfo: CompileFileInfo): void {
    const source = fs.readFileSync(fileInfo.filePath, 'utf8');
    let moduleInfo: ModuleInfo = this.moduleInfos.get(fileInfo.packageName)!;
    let filePathFromModuleRoot: string = path.relative(moduleInfo.moduleRootPath, fileInfo.filePath);
    let declEtsOutputPath: string = changeDeclgenFileExtension(
      path.join(moduleInfo.declgenV1OutPath as string, moduleInfo.packageName, filePathFromModuleRoot),
      DECL_ETS_SUFFIX
    );
    let etsOutputPath: string = changeDeclgenFileExtension(
      path.join(moduleInfo.declgenBridgeCodePath as string, moduleInfo.packageName, filePathFromModuleRoot),
      TS_SUFFIX
    );
    ensurePathExists(declEtsOutputPath);
    ensurePathExists(etsOutputPath);
    let arktsGlobal: ArkTSGlobal = this.buildConfig.arktsGlobal;
    let arkts: ArkTS = this.buildConfig.arkts;
    let errorStatus = false;
    try {
      arktsGlobal.filePath = fileInfo.filePath;
      arktsGlobal.config = arkts.Config.create([
        '_',
        '--extension',
        'ets',
        '--arktsconfig',
        fileInfo.arktsConfigFile,
        fileInfo.filePath
      ]).peer;
      arktsGlobal.compilerContext = arkts.Context.createFromString(source);
      PluginDriver.getInstance().getPluginContext().setArkTSProgram(arktsGlobal.compilerContext.program);

      arkts.proceedToState(arkts.Es2pandaContextState.ES2PANDA_STATE_PARSED, true);

      let ast = arkts.EtsScript.fromContext();
      PluginDriver.getInstance().getPluginContext().setArkTSAst(ast);
      PluginDriver.getInstance().runPluginHook(PluginHook.PARSED);

      arkts.proceedToState(arkts.Es2pandaContextState.ES2PANDA_STATE_CHECKED, true);

      ast = arkts.EtsScript.fromContext();
      PluginDriver.getInstance().getPluginContext().setArkTSAst(ast);
      PluginDriver.getInstance().runPluginHook(PluginHook.CHECKED);

      arkts.generateTsDeclarationsFromContext(
        declEtsOutputPath,
        etsOutputPath,
        false
      ); // Generate 1.0 declaration files & 1.0 glue code
      this.logger.printInfo('declaration files generated');
    } catch (error) {
      errorStatus = true;
      if (error instanceof Error) {
        const logData: LogData = LogDataFactory.newInstance(
          ErrorCode.BUILDSYSTEM_DECLGEN_FAIL,
          'Generate declaration files failed.',
          error.message
        );
        this.logger.printError(logData);
      }
    } finally {
      if (!errorStatus) {
        // when error occur,wrapper will destroy context.
        arktsGlobal.es2panda._DestroyContext(arktsGlobal.compilerContext.peer);
      }
      arkts.destroyConfig(arktsGlobal.config);
    }
  }

  public compile(fileInfo: CompileFileInfo): void {
    ensurePathExists(fileInfo.abcFilePath);

    let ets2pandaCmd: string[] = [
      '_',
      '--extension',
      'ets',
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

    let arktsGlobal = this.buildConfig.arktsGlobal;
    let arkts = this.buildConfig.arkts;
    let errorStatus = false;
    try {
      arktsGlobal.filePath = fileInfo.filePath;
      arktsGlobal.config = arkts.Config.create(ets2pandaCmd).peer;
      const source = fs.readFileSync(fileInfo.filePath).toString();
      arktsGlobal.compilerContext = arkts.Context.createFromString(source);
      PluginDriver.getInstance().getPluginContext().setArkTSProgram(arktsGlobal.compilerContext.program);

      arkts.proceedToState(arkts.Es2pandaContextState.ES2PANDA_STATE_PARSED);
      this.logger.printInfo('es2panda proceedToState parsed');
      let ast = arkts.EtsScript.fromContext();
      PluginDriver.getInstance().getPluginContext().setArkTSAst(ast);
      PluginDriver.getInstance().runPluginHook(PluginHook.PARSED);
      this.logger.printInfo('plugin parsed finished');

      arkts.proceedToState(arkts.Es2pandaContextState.ES2PANDA_STATE_CHECKED);
      this.logger.printInfo('es2panda proceedToState checked');
      ast = arkts.EtsScript.fromContext();
      PluginDriver.getInstance().getPluginContext().setArkTSAst(ast);
      PluginDriver.getInstance().runPluginHook(PluginHook.CHECKED);
      this.logger.printInfo('plugin checked finished');

      arkts.proceedToState(arkts.Es2pandaContextState.ES2PANDA_STATE_BIN_GENERATED);
      this.logger.printInfo('es2panda bin generated');
    } catch (error) {
      errorStatus = true;
      if (error instanceof Error) {
        const logData: LogData = LogDataFactory.newInstance(
          ErrorCode.BUILDSYSTEM_COMPILE_ABC_FAIL,
          'Compile abc files failed.',
          error.message
        );
        this.logger.printError(logData);
      }
    } finally {
      if (!errorStatus) {
        // when error occur,wrapper will destroy context.
        arktsGlobal.es2panda._DestroyContext(arktsGlobal.compilerContext.peer);
      }
      PluginDriver.getInstance().runPluginHook(PluginHook.CLEAN);
      arkts.destroyConfig(arktsGlobal.config);
    }
  }

  public mergeAbcFiles(): void {
    let linkerInputFile: string = path.join(this.cacheDir, LINKER_INPUT_FILE);
    let linkerInputContent: string = '';
    this.abcFiles.forEach((abcFile: string) => {
      linkerInputContent += abcFile + os.EOL;
    });
    fs.writeFileSync(linkerInputFile, linkerInputContent);

    this.abcLinkerCmd.push('--output');
    this.abcLinkerCmd.push('"' + this.mergedAbcFile + '"');
    this.abcLinkerCmd.push('--');
    this.abcLinkerCmd.push('@' + '"' + linkerInputFile + '"');

    let abcLinkerCmdStr: string = this.abcLinkerCmd.join(' ');
    if (isMac()) {
      const loadLibrary = 'DYLD_LIBRARY_PATH=' + '"' + process.env.DYLD_LIBRARY_PATH + '"';
      abcLinkerCmdStr = loadLibrary + ' ' + abcLinkerCmdStr;
    }
    this.logger.printInfo(abcLinkerCmdStr);

    ensurePathExists(this.mergedAbcFile);
    try {
      child_process.execSync(abcLinkerCmdStr).toString();
    } catch (error) {
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

  private getDependentModules(moduleInfo: ModuleInfo): Map<string, ModuleInfo>[] {
    let dynamicDepModules: Map<string, ModuleInfo> = new Map<string, ModuleInfo>();
    let staticDepModules: Map<string, ModuleInfo> = new Map<string, ModuleInfo>();

    if (moduleInfo.isMainModule) {
      this.moduleInfos.forEach((module: ModuleInfo, packageName: string) => {
        if (module.isMainModule) {
          return;
        }
        module.language === LANGUAGE_VERSION.ARKTS_1_2 ?
          staticDepModules.set(packageName, module) : dynamicDepModules.set(packageName, module);
      });
      return [dynamicDepModules, staticDepModules];
    }

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
          depModuleInfo.language === LANGUAGE_VERSION.ARKTS_1_2 ?
            staticDepModules.set(packageName, depModuleInfo) : dynamicDepModules.set(packageName, depModuleInfo);
        }
      });
    }
    return [dynamicDepModules, staticDepModules];
  }

  protected generateArkTSConfigForModules(): void {
    this.moduleInfos.forEach((moduleInfo: ModuleInfo, moduleRootPath: string) => {
      ArkTSConfigGenerator.getInstance(this.buildConfig, this.moduleInfos).writeArkTSConfigFile(moduleInfo);
    });
  }

  private collectDepModuleInfos(): void {
    this.moduleInfos.forEach((moduleInfo) => {
      let [dynamicDepModules, staticDepModules] = this.getDependentModules(moduleInfo);
      moduleInfo.dynamicDepModuleInfos = dynamicDepModules;
      moduleInfo.staticDepModuleInfos = staticDepModules;
    });
  }

  protected collectModuleInfos(): void {
    if (this.hasMainModule && (!this.packageName || !this.moduleRootPath || !this.sourceRoots)) {
      const logData: LogData = LogDataFactory.newInstance(
        ErrorCode.BUILDSYSTEM_MODULE_INFO_NOT_CORRECT_FAIL,
        'Main module info from hvigor is not correct.'
      );
      this.logger.printError(logData);
    }
    let mainModuleInfo: ModuleInfo = this.getMainModuleInfo();
    this.moduleInfos.set(this.packageName, mainModuleInfo);
    this.dependentModuleList.forEach((module: DependentModuleConfig) => {
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
        moduleType: module.moduleType,
        sourceRoots: module.sourceRoots,
        entryFile: module.entryFile,
        arktsConfigFile: path.resolve(this.cacheDir, module.packageName, ARKTSCONFIG_JSON_FILE),
        compileFileInfos: [],
        dynamicDepModuleInfos: new Map<string, ModuleInfo>(),
        staticDepModuleInfos: new Map<string, ModuleInfo>(),
        declgenV1OutPath: module.declgenV1OutPath,
        declgenBridgeCodePath: module.declgenBridgeCodePath,
        language: module.language,
        declFilesPath: module.declFilesPath,
        dependencies: module.dependencies
      };
      this.moduleInfos.set(module.packageName, moduleInfo);
    });
    this.collectDepModuleInfos();
  }

  protected getMainModuleInfo(): ModuleInfo {
    return {
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
  }

  private loadHashCache(): Record<string, string> {
    try {
      if (fs.existsSync(this.hashCacheFile)) {
        const cacheContent = fs.readFileSync(this.hashCacheFile, 'utf-8');
        return JSON.parse(cacheContent);
      }
    } catch (error) {
      if (error instanceof Error) {
        const logData: LogData = LogDataFactory.newInstance(
          ErrorCode.BUILDSYSTEM_LOAD_HASH_CACHE_FAIL,
          'Failed to load hash cache.',
          error.message
        );
        this.logger.printError(logData);
      }
    }
    return {};
  }

  private saveHashCache(): void {
    ensurePathExists(this.hashCacheFile);
    fs.writeFileSync(this.hashCacheFile, JSON.stringify(this.hashCache, null, 2));
  }

  private isFileChanged(etsFilePath: string, abcFilePath: string): boolean {
    if (fs.existsSync(abcFilePath)) {
      const etsFileLastModified: number = fs.statSync(etsFilePath).mtimeMs;
      const abcFileLastModified: number = fs.statSync(abcFilePath).mtimeMs;
      if (etsFileLastModified < abcFileLastModified) {
        const currentHash = getFileHash(etsFilePath);
        const cachedHash = this.hashCache[etsFilePath];
        if (cachedHash && currentHash === cachedHash) {
          return false;
        }
      }
    }
    return true;
  }

  private collectDependentCompileFiles(): void {
    if (!this.dependencyFileMap) {
      const logData: LogData = LogDataFactory.newInstance(
        ErrorCode.BUILDSYSTEM_Dependency_Analyze_FAIL,
        'Analyze files dependency failed.',
        'Dependency map not initialized.'
      );
      this.logger.printError(logData);
      return;
    }

    const compileFiles = new Set<string>();
    const processed = new Set<string>();
    const queue: string[] = [];

    this.entryFiles.forEach((file: string) => {
      let hasModule = false;
      for (const [packageName, moduleInfo] of this.moduleInfos) {
        if (!file.startsWith(moduleInfo.moduleRootPath)) {
          continue;
        }

        hasModule = true;
        const filePathFromModuleRoot = path.relative(moduleInfo.moduleRootPath, file);
        const filePathInCache = path.join(this.cacheDir, moduleInfo.packageName, filePathFromModuleRoot);
        const abcFilePath = path.resolve(changeFileExtension(filePathInCache, ABC_SUFFIX));
        this.abcFiles.add(abcFilePath);

        const fileInfo: CompileFileInfo = {
          filePath: file,
          dependentFiles: this.dependencyFileMap?.dependants[file] || [],
          abcFilePath,
          arktsConfigFile: moduleInfo.arktsConfigFile,
          packageName: moduleInfo.packageName
        };
        this.allFiles.set(file, fileInfo);

        if (this.isBuildConfigModified || this.isFileChanged(file, abcFilePath)) {
          compileFiles.add(file);
          queue.push(file);
        }
        this.hashCache[file] = getFileHash(file);
        break;
      }
      if (!hasModule) {
        const logData: LogData = LogDataFactory.newInstance(
          ErrorCode.BUILDSYSTEM_FILE_NOT_BELONG_TO_ANY_MODULE_FAIL,
          'File does not belong to any module in moduleInfos.',
          '',
          file
        );
        this.logger.printError(logData);
        return;
      }
    });

    while (queue.length > 0) {
      const currentFile = queue.shift()!;
      processed.add(currentFile);

      (this.dependencyFileMap?.dependants[currentFile] || []).forEach(dependant => {
        if (!compileFiles.has(dependant) && !processed.has(dependant)) {
          queue.push(dependant);
        }
        compileFiles.add(dependant);
      });
    }

    compileFiles.forEach((file: string) => {
      let hasModule = false;
      for (const [packageName, moduleInfo] of this.moduleInfos) {
        if (!file.startsWith(moduleInfo.moduleRootPath)) {
          continue;
        }
        hasModule = true;
        const filePathFromModuleRoot = path.relative(moduleInfo.moduleRootPath, file);
        const filePathInCache = path.join(this.cacheDir, moduleInfo.packageName, filePathFromModuleRoot);
        const abcFilePath = path.resolve(changeFileExtension(filePathInCache, ABC_SUFFIX));

        const fileInfo: CompileFileInfo = {
          filePath: file,
          dependentFiles: this.dependencyFileMap?.dependants[file] || [],
          abcFilePath,
          arktsConfigFile: moduleInfo.arktsConfigFile,
          packageName: moduleInfo.packageName
        };

        moduleInfo.compileFileInfos.push(fileInfo);
        this.compileFiles.set(file, fileInfo);
        break;
      }
      if (!hasModule) {
        const logData: LogData = LogDataFactory.newInstance(
          ErrorCode.BUILDSYSTEM_FILE_NOT_BELONG_TO_ANY_MODULE_FAIL,
          'File does not belong to any module in moduleInfos.',
          '',
          file
        );
        this.logger.printError(logData);
      }
    });
  }
  
  private shouldSkipFile(file: string, moduleInfo: ModuleInfo, filePathFromModuleRoot: string, abcFilePath: string): boolean {
    const targetPath = this.enableDeclgenEts2Ts
        ? changeFileExtension(path.join(moduleInfo.declgenBridgeCodePath as string, moduleInfo.packageName, filePathFromModuleRoot), TS_SUFFIX)
        : abcFilePath;
    return !this.isFileChanged(file, targetPath);
  }

  protected collectCompileFiles(): void {
    if (!this.enableDeclgenEts2Ts) {
      this.collectDependentCompileFiles();
      return;
    }
    this.entryFiles.forEach((file: string) => {
      for (const [packageName, moduleInfo] of this.moduleInfos) {
        if (!file.startsWith(moduleInfo.moduleRootPath)) {
          continue;
        }
        let filePathFromModuleRoot: string = path.relative(moduleInfo.moduleRootPath, file);
        let filePathInCache: string = path.join(this.cacheDir, moduleInfo.packageName, filePathFromModuleRoot);
        let abcFilePath: string = path.resolve(changeFileExtension(filePathInCache, ABC_SUFFIX));
        this.abcFiles.add(abcFilePath);
        this.hashCache[file] = getFileHash(file);
        let fileInfo: CompileFileInfo = {
          filePath: path.resolve(file),
          dependentFiles: [],
          abcFilePath: abcFilePath,
          arktsConfigFile: moduleInfo.arktsConfigFile,
          packageName: moduleInfo.packageName
        };
        moduleInfo.compileFileInfos.push(fileInfo);
        this.compileFiles.set(path.resolve(file), fileInfo);
        return;
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

  protected generateModuleInfos(): void {
    this.collectModuleInfos();
    this.generateArkTSConfigForModules();
    this.generatedependencyFileMap();
    this.collectCompileFiles();
    this.saveHashCache();
  }

  public async generateDeclaration(): Promise<void> {
    this.generateModuleInfos();

    const compilePromises: Promise<void>[] = [];
    this.compileFiles.forEach((fileInfo: CompileFileInfo, file: string) => {
      compilePromises.push(new Promise<void>((resolve) => {
        this.declgen(fileInfo);
        resolve();
      }));
    });
    await Promise.all(compilePromises);
  }

  public async run(): Promise<void> {
    this.generateModuleInfos();

    const compilePromises: Promise<void>[] = [];
    this.compileFiles.forEach((fileInfo: CompileFileInfo, file: string) => {
      compilePromises.push(new Promise<void>((resolve) => {
        this.compile(fileInfo);
        resolve();
      }));
    });
    await Promise.all(compilePromises);

    this.mergeAbcFiles();
  }

  // -- runParallell code begins --
  private terminateAllWorkers(): void {
    Object.values(cluster.workers || {}).forEach(worker => {
      worker?.kill();
    });
  };

  public generatedependencyFileMap(): void {
    if (this.enableDeclgenEts2Ts) {
      return;
    }
    let dependencyInputFile: string = path.join(this.cacheDir, DEPENDENCY_INPUT_FILE);
    let dependencyInputContent: string = '';
    this.entryFiles.forEach((entryFile: string) => {
      dependencyInputContent += entryFile + os.EOL;
    });
    fs.writeFileSync(dependencyInputFile, dependencyInputContent);

    this.dependencyAnalyzerCmd.push('@' + '"' + dependencyInputFile + '"');
    for (const [packageName, module] of this.moduleInfos) {
      if (module.isMainModule) {
          this.dependencyAnalyzerCmd.push('--arktsconfig=' + '"' + module.arktsConfigFile + '"');
          break;
      }
    }
    this.dependencyAnalyzerCmd.push('--output=' + '"' + this.dependencyJsonFile + '"');
    let dependencyAnalyzerCmdStr: string = this.dependencyAnalyzerCmd.join(' ');
    if (isMac()) {
      const loadLibrary = 'DYLD_LIBRARY_PATH=' + '"' + process.env.DYLD_LIBRARY_PATH + '"';
      dependencyAnalyzerCmdStr = loadLibrary + ' ' + dependencyAnalyzerCmdStr;
    }
    this.logger.printInfo(dependencyAnalyzerCmdStr);

    ensurePathExists(this.dependencyJsonFile);
    try {
      const output = child_process.execSync(dependencyAnalyzerCmdStr, { 
        stdio: 'pipe',
        encoding: 'utf-8'
      });
      if (output.trim() !== '') {
        const logData: LogData = LogDataFactory.newInstance(
          ErrorCode.BUILDSYSTEM_Dependency_Analyze_FAIL,
          'Analyze files dependency failed.',
          output
        );
        this.logger.printError(logData);
        return;
      }
      const dependencyJsonContent = fs.readFileSync(this.dependencyJsonFile, 'utf-8');
      this.dependencyFileMap = JSON.parse(dependencyJsonContent);
    } catch (error) {
      if (error instanceof Error) {
        const execError = error as child_process.ExecException;
        let fullErrorMessage = execError.message;
        if (execError.stderr) {
            fullErrorMessage += `\nError output: ${execError.stderr}`;
        }
        if (execError.stdout) {
            fullErrorMessage += `\nOutput: ${execError.stdout}`;
        }
        const logData: LogData = LogDataFactory.newInstance(
          ErrorCode.BUILDSYSTEM_Dependency_Analyze_FAIL,
          'Analyze files dependency failed.',
          fullErrorMessage
        );
        this.logger.printError(logData);
      }
    }
  }

  public async runParallell(): Promise<void> {
    this.generateModuleInfos();

    if (!cluster.isPrimary) {
      return;
    }

    try {
      this.setupCluster(cluster, {
        clearExitListeners: true,
        execPath: path.resolve(__dirname, 'compile_worker.js'),
      });
      await this.dispatchTasks();
      this.logger.printInfo('All tasks complete, merging...');
      this.mergeAbcFiles();
    } catch (error) {
      this.logger.printError(LogDataFactory.newInstance(
        ErrorCode.BUILDSYSTEM_COMPILE_ABC_FAIL,
        'Compile abc files failed.'
      ));
    } finally {
      this.terminateAllWorkers();
    }
  }

  public async generateDeclarationParallell(): Promise<void> {
    this.generateModuleInfos();
    this.generateArkTSConfigForModules();

    if (!cluster.isPrimary) {
      return;
    }

    try {
      this.setupCluster(cluster, {
        clearExitListeners: true,
        execPath: path.resolve(__dirname, 'declgen_worker.js'),
      });
      await this.dispatchTasks();
      this.logger.printInfo('All declaration generation tasks complete.');
    } catch (error) {
        this.logger.printError(LogDataFactory.newInstance(
        ErrorCode.BUILDSYSTEM_DECLGEN_FAIL,
        'Generate declaration files failed.'
      ));
    } finally {
      this.terminateAllWorkers();
    }
  }

  private async dispatchTasks(): Promise<void> {
    const numCPUs = os.cpus().length;
    const taskQueue = Array.from(this.compileFiles.values());

    const configuredWorkers = this.buildConfig?.maxWorkers;
    const defaultWorkers = DEFAULT_WOKER_NUMS;

    let effectiveWorkers: number;

    if (configuredWorkers) {
      effectiveWorkers = Math.min(configuredWorkers, numCPUs - 1);
    } else {
      effectiveWorkers = Math.min(defaultWorkers, numCPUs - 1);
    }

    const maxWorkers = Math.min(taskQueue.length, effectiveWorkers);

    const chunkSize = Math.ceil(taskQueue.length / maxWorkers);
    const serializableConfig = this.getSerializableConfig();
    const workerExitPromises: Promise<void>[] = [];

    const moduleInfosArray = Array.from(this.moduleInfos.entries());

    for (let i = 0; i < maxWorkers; i++) {
      const taskChunk = taskQueue.slice(i * chunkSize, (i + 1) * chunkSize);
      const worker = cluster.fork();

      this.setupWorkerMessageHandler(worker);
      worker.send({ taskList: taskChunk, buildConfig: serializableConfig, moduleInfos: moduleInfosArray});

      const exitPromise = new Promise<void>((resolve, reject) => {
        worker.on('exit', (status) => status === 0 ? resolve() : reject());
      });

      workerExitPromises.push(exitPromise);
    }

    await Promise.all(workerExitPromises);
  }

  private setupWorkerMessageHandler(worker: Worker): void {
    worker.on('message', (message: {
      success: boolean;
      filePath?: string;
      error?: string;
    }) => {
      if (message.success) {
        return;
      }
      this.logger.printError(LogDataFactory.newInstance(
        ErrorCode.BUILDSYSTEM_COMPILE_ABC_FAIL,
        'Compile abc files failed in worker.',
        message.error || 'Unknown error',
        message.filePath
      ));
    });
  }

  private getSerializableConfig(): Object {
    const ignoreList = [
      'arkts',
    ];
    const jsonStr = JSON.stringify(this.buildConfig, (key, value) => {
      if (typeof value === 'bigint') {
        return undefined;
      }
      //remove useless data from buildConfig
      if (ignoreList.includes(key)) {
        return undefined;
      }
      return value;
    });
    return JSON.parse(jsonStr);
  }
  setupCluster(cluster: Cluster, options: SetupClusterOptions): void {
    const {
      clearExitListeners,
      execPath,
      execArgs = [],
    } = options;
  
    if (clearExitListeners) {
      cluster.removeAllListeners('exit');
    }
  
    cluster.setupPrimary({
      exec: execPath,
      execArgv: execArgs,
    });
  }
  // -- runParallell code ends --


  // -- runConcurrent code begins --

  private findStronglyConnectedComponents(graph: DependencyFileConfig): Map<string, Set<string>> {
    const adjacencyList: Record<string, string[]> = {};
    const reverseAdjacencyList: Record<string, string[]> = {};
    const allNodes = new Set<string>();

    for (const node in graph.dependencies) {
        allNodes.add(node);
        graph.dependencies[node].forEach(dep => allNodes.add(dep));
    }
    for (const node in graph.dependants) {
        allNodes.add(node);
        graph.dependants[node].forEach(dep => allNodes.add(dep));
    }

    Array.from(allNodes).forEach(node => {
        adjacencyList[node] = graph.dependencies[node] || [];
        reverseAdjacencyList[node] = graph.dependants[node] || [];
    });

    const visited = new Set<string>();
    const order: string[] = [];

    function dfs(node: string): void {
        visited.add(node);
        for (const neighbor of adjacencyList[node]) {
            if (!visited.has(neighbor)) {
                dfs(neighbor);
            }
        }
        order.push(node);
    }

    Array.from(allNodes).forEach(node => {
        if (!visited.has(node)) {
            dfs(node);
        }
    });

    visited.clear();
    const components = new Map<string, Set<string>>();

    function reverseDfs(node: string, component: Set<string>): void {
        visited.add(node);
        component.add(node);
        for (const neighbor of reverseAdjacencyList[node]) {
            if (!visited.has(neighbor)) {
                reverseDfs(neighbor, component);
            }
        }
    }

    for (let i = order.length - 1; i >= 0; i--) {
        const node = order[i];
        if (!visited.has(node)) {
            const component = new Set<string>();
            reverseDfs(node, component);
            if (component.size > 1) {
              const sortedFiles = Array.from(component).sort();
              const hashKey = createHash(sortedFiles.join('|'));
              components.set(hashKey, component);
            }

        }
    }

    return components;
  }


  private getJobDependencies(fileDeps: string[], cycleFiles: Map<string, string[]>): Set<string> {
    let depJobList: Set<string> = new Set<string>();
    fileDeps.forEach((file) => {
      if (!cycleFiles.has(file)) {
        depJobList.add(this.getExternalProgramJobId(file));
      } else {
        cycleFiles.get(file)?.forEach((f) => {
          depJobList.add(f);
        });
      }
    });

    return depJobList;
  }

  private getAbcJobId(file: string): string {
    return '1' + file;
  }
  
  private getExternalProgramJobId(file: string): string {
    return '0' + file;
  }

  private getJobDependants(fileDeps: string[], cycleFiles: Map<string, string[]>): Set<string> {
    let depJobList: Set<string> = new Set<string>();
    fileDeps.forEach((file) => {  
      if (!file.endsWith(DECL_ETS_SUFFIX)) {
        depJobList.add(this.getAbcJobId(file));
      }
      if (cycleFiles.has(file)) {
        cycleFiles.get(file)?.forEach((f) => {
          depJobList.add(f);
        });
      } else {
        depJobList.add(this.getExternalProgramJobId(file));
      }
    });

    return depJobList;
  }

  private collectCompileJobs(jobs: Record<string, Job>): void {
    let fileDepsInfo: DependencyFileConfig = this.dependencyFileMap!;
    Object.keys(fileDepsInfo.dependants).forEach((file) => {
      if (!(file in fileDepsInfo.dependencies)) {
        fileDepsInfo.dependencies[file] = [];
      }
    });

    const cycleGroups = this.findStronglyConnectedComponents(fileDepsInfo);
    let cycleFiles: Map<string, string[]> = new Map<string, string[]>();
    cycleGroups.forEach((value: Set<string>, key: string) => {
      value.forEach((file) => {
        cycleFiles.set(file, [key]);
      });
    });

    Object.entries(fileDepsInfo.dependencies).forEach(([key, value]) => {
      if (this.entryFiles.has(key) && !this.compileFiles.has(key)) {
        return;
      }
      let dependencies = this.getJobDependencies(value, cycleFiles);

      if (!key.endsWith(DECL_ETS_SUFFIX)) {
        let abcJobId: string = this.getAbcJobId(key);
        jobs[abcJobId] = {
          id: abcJobId,
          isDeclFile: false,
          isInCycle: cycleFiles.has(key),
          isAbcJob: true,
          fileList: [key],
          dependencies: Array.from(dependencies), // 依赖external program
          dependants: []
        };
      }

      if (cycleFiles.has(key)) {
        const externalProgramJobIds = cycleFiles.get(key)!;
        externalProgramJobIds.forEach((id) => {
          let fileList: string[] = Array.from(cycleGroups.get(id)!);
          this.createExternalProgramJob(id, fileList, jobs, dependencies, true);
        });
      } else {
        const id = this.getExternalProgramJobId(key);
        let fileList: string[] = [key];
        this.createExternalProgramJob(id, fileList, jobs, dependencies);
      }

      if (key.endsWith(DECL_ETS_SUFFIX)) {
        let fileInfo: CompileFileInfo = {
          filePath: key,
          dependentFiles: [],
          abcFilePath: '',
          arktsConfigFile: this.moduleInfos.get(this.packageName)!.arktsConfigFile,
          packageName: this.moduleInfos.get(this.packageName)!.packageName
        };

        if (!this.allFiles.has(key)) {
          this.allFiles.set(key, fileInfo);
        }
      }
    });

    Object.entries(fileDepsInfo.dependants).forEach(([key, value]) => {
      if (this.entryFiles.has(key) && !this.compileFiles.has(key)) {
        return;
      }
      let dependants = this.getJobDependants(value, cycleFiles);

      this.dealWithDependants(cycleFiles, key, jobs, dependants);
    });
  }

  private dealWithDependants(cycleFiles: Map<string, string[]>, key: string, jobs: Record<string, Job>, dependants: Set<string>): void {
    if (cycleFiles.has(key)) {
      const externalProgramJobIds = cycleFiles.get(key)!;
      externalProgramJobIds.forEach((id) => {
        jobs[id].dependants.forEach(dep => {
          dependants.add(dep);
        });
        if (dependants.has(id)) {
          dependants.delete(id);
        }

        jobs[id].dependants = Array.from(dependants);
      });
    } else {
      const id = this.getExternalProgramJobId(key);
      jobs[id].dependants.forEach(dep => {
        dependants.add(dep);
      });
      if (dependants.has(id)) {
        dependants.delete(id);
      }
      jobs[id].dependants = Array.from(dependants);
    }
  }

  private createExternalProgramJob(id: string, fileList: string[], jobs: Record<string, Job>, dependencies: Set<string>, isInCycle?: boolean): void {
    if (dependencies.has(id)) {
      dependencies.delete(id);
    }

    // TODO: can be duplicated ids
    if (jobs[id]) {
      // If job already exists, merge the file lists and dependencies
      const existingJob = jobs[id];
      const mergedDependencies = new Set([
        ...existingJob.dependencies,
        ...Array.from(dependencies)
      ]);
      jobs[id] = {
        ...existingJob,
        dependencies: Array.from(mergedDependencies)
      };
    } else {
      jobs[id] = {
        id,
        fileList,
        isDeclFile: true,
        isInCycle,
        isAbcJob: false,
        dependencies: Array.from(dependencies), // 依赖external program
        dependants: []
      };
    }
  }

  private addJobToQueues(job: Job, queues: Queues): void {
    if (queues.externalProgramQueue.some(j => j.id === job.id) ||
      queues.abcQueue.some(j => j.id === job.id)) {
      return;
    }

    if (!job.isAbcJob) {
      queues.externalProgramQueue.push(job);
    } else {
      queues.abcQueue.push(job);
    }
  }

  private initCompileQueues(jobs: Record<string, Job>, queues: Queues): void {
    this.collectCompileJobs(jobs);
    Object.values(jobs).forEach(job => {
      if (job.dependencies.length === 0) {
        this.addJobToQueues(job, queues);
      }
    });
  }

  private checkAllTasksDone(queues: Queues, workerPool: WorkerInfo[]): boolean {
    if (queues.externalProgramQueue.length === 0) {
      for (let i = 0; i < workerPool.length; i++) {
        if (!workerPool[i].isIdle) {
          return false;
        }
      }
      return true;
    }
    return false;
  }

  private processAfterCompile(config: KPointer, globalContext: KPointer): void {

    if (this.hasCleanWorker) {
      return;
    }
    this.hasCleanWorker = true;
    let arktsGlobal = this.buildConfig.arktsGlobal;
    let arkts = this.buildConfig.arkts;

    arktsGlobal.es2panda._DestroyGlobalContext(globalContext);
    arkts.destroyConfig(config);
    arktsGlobal.es2panda._MemFinalize();

    this.mergeAbcFiles();
  }

  // CC-OFFNXT(huge_depth)
  private async invokeWorkers(jobs: Record<string, Job>, queues: Queues, processingJobs: Set<string>, workers: ThreadWorker[]): Promise<void> {
    return new Promise<void>((resolve) => {
      const numWorkers = 1;

      let files: string[] = [];

      Object.entries(jobs).forEach(([key, job]) => {
        for (let i = 0; i < job.fileList.length; i++) {
          files.push(job.fileList[i]);
        }
      });

      let arkts = this.buildConfig.arkts;
      let fileInfo = this.compileFiles.values().next().value!;

      let ets2pandaCmd: string[] = [
        '_',
        '--extension',
        'ets',
        '--arktsconfig',
        fileInfo.arktsConfigFile,
        '--output',
        fileInfo.abcFilePath,
      ];
  
      if (this.isDebug) {
        ets2pandaCmd.push('--debug-info');
      }
      ets2pandaCmd.push(fileInfo.filePath);

      arkts.MemInitialize();

      let config = arkts.Config.create(ets2pandaCmd).peer;

      let globalContextPtr = arkts.CreateGlobalContext(config, files, files.length, false);
      const serializableConfig = this.getSerializableConfig();

      const workerPool: WorkerInfo[] = [];
      for (let i = 0; i < numWorkers; i++) {
        const worker = new ThreadWorker(
          path.resolve(__dirname, 'compile_thread_worker.js'),
          { workerData: { workerId: i } }
        );

        workers.push(worker);
        workerPool.push({ worker, isIdle: true });
        this.assignTaskToIdleWorker(workerPool[i], queues, processingJobs, serializableConfig, globalContextPtr);
        worker.on('message', (msg) => {
          if (msg.type === 'TASK_FINISH') {
            const workerInfo = workerPool.find(w => w.worker === worker);
            if (workerInfo) {
              workerInfo.isIdle = true;
            }
            const jobId = msg.jobId;
            finishedJob.push(jobId);
            processingJobs.delete(jobId);
            const completedJob = jobs[jobId];
            completedJob.dependants.forEach(depJobId => {
              const depJob = jobs[depJobId];
              if (!depJob) {
                return;
              }
              const depIndex = depJob.dependencies.indexOf(jobId);
              if (depIndex !== -1) {
                depJob.dependencies.splice(depIndex, 1);
                if (depJob.dependencies.length === 0) {
                  this.addJobToQueues(depJob, queues);
                }
              }
            });
            for (let j = 0; j < workerPool.length; j++) {
              if (workerPool[j].isIdle) {
                this.assignTaskToIdleWorker(workerPool[j], queues, processingJobs, serializableConfig, globalContextPtr);
              }
            }
          }
          if (this.checkAllTasksDone(queues, workerPool)) {
            workers.forEach(worker => worker.postMessage({ type: 'EXIT' }));
            this.processAfterCompile(config, globalContextPtr);
            resolve();
          }
        });
      }
    });
  }

  private updateDependantJobs(jobId: string, processingJobs: Set<string>, jobs: Record<string, Job>, queues: Queues): void {
    finishedJob.push(jobId);
    processingJobs.delete(jobId);
    const completedJob = jobs[jobId];
    completedJob.dependants.forEach(depJobId => {
      const depJob = jobs[depJobId];
      // During incremental compilation, the dependants task does not necessarily exist
      if (!depJob) {
        return;
      }
      const depIndex = depJob.dependencies.indexOf(jobId);
      if (depIndex !== -1) {
        depJob.dependencies.splice(depIndex, 1);
        if (depJob.dependencies.length === 0) {
          this.addJobToQueues(depJob, queues);
        }
      }
    });
  }

  private assignTaskToIdleWorker(
    workerInfo: WorkerInfo, 
    queues: Queues, 
    processingJobs: Set<string>, 
    serializableConfig: Object, 
    globalContextPtr: KPointer): void {
    let job: Job | undefined;
    let jobInfo: JobInfo | undefined;

    if (queues.externalProgramQueue.length > 0) {
      job = queues.externalProgramQueue.shift()!;
      jobInfo = {
        id: job.id,
        isCompileAbc: false,
        compileFileInfo: this.allFiles.get(job.fileList[0])!,
        buildConfig: serializableConfig,
        globalContextPtr: globalContextPtr
      };
    } 
    else if (queues.abcQueue.length > 0) {
      job = queues.abcQueue.shift()!;
      jobInfo = {
        id: job.id,
        isCompileAbc: true,
        compileFileInfo: this.allFiles.get(job.fileList[0])!,
        buildConfig: serializableConfig,
        globalContextPtr: globalContextPtr
      };
    }

    if (job) {
      processingJobs.add(job.id);
      workerInfo.worker.postMessage({ type: 'ASSIGN_TASK', jobInfo });
      workerInfo.isIdle = false;
    }
  }

  public async runConcunrent(): Promise<void> {
    this.generateModuleInfos();
    if (this.compileFiles.size === 0) {
      return;
    }
    this.generateArkTSConfigForModules();

    const jobs: Record<string, Job> = {};
    const queues: Queues = {
      externalProgramQueue: [],
      abcQueue: [],
    };
    this.initCompileQueues(jobs, queues);

    const processingJobs = new Set<string>();
    const workers: ThreadWorker[] = [];
    await this.invokeWorkers(jobs, queues, processingJobs, workers);
  }
}

interface WorkerInfo {
  worker: ThreadWorker;
  isIdle: boolean;
}

interface Job {
  id: string;
  isDeclFile: boolean;
  isInCycle?: boolean;
  fileList: string[];
  dependencies: string[];
  dependants: string[];
  isAbcJob: boolean;
}

interface Queues {
  externalProgramQueue: Job[];
  abcQueue: Job[];
}

function createHash(str: string): string {
  const hash = crypto.createHash('sha256');
  hash.update(str);
  return hash.digest('hex');
}

  // -- runConcurrent code ends --

let finishedJob: string[] = [];