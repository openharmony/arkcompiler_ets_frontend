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
import cluster, {
  Cluster,
  Worker
} from 'cluster';
import {
  ABC_SUFFIX,
  ARKTSCONFIG_JSON_FILE,
  BUILD_MODE,
  DEFAULT_WOKER_NUMS,
  DECL_ETS_SUFFIX,
  DECL_TS_SUFFIX,
  DEPENDENCY_INPUT_FILE,
  DEPENDENCY_JSON_FILE,
  LANGUAGE_VERSION,
  LINKER_INPUT_FILE,
  MERGED_ABC_FILE,
  STATIC_RECORD_FILE,
  STATIC_RECORD_FILE_CONTENT,
  TS_SUFFIX
} from '../pre_define';
import {
  changeDeclgenFileExtension,
  changeFileExtension,
  createFileIfNotExists,
  ensurePathExists,
  getFileHash,
  isHybrid,
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
  ModuleInfo
} from '../types';
import { ArkTSConfigGenerator } from './generate_arktsconfig';
import { SetupClusterOptions } from '../types';

export abstract class BaseMode {
  public buildConfig: BuildConfig;
  public entryFiles: Set<string>;
  public compileFiles: Map<string, CompileFileInfo>;
  public outputDir: string;
  public cacheDir: string;
  public pandaSdkPath: string;
  public buildSdkPath: string;
  public packageName: string;
  public sourceRoots: string[];
  public moduleRootPath: string;
  public moduleType: string;
  public dependentModuleList: DependentModuleConfig[];
  public moduleInfos: Map<string, ModuleInfo>;
  public mergedAbcFile: string;
  public dependencyJsonFile: string;
  public abcLinkerCmd: string[];
  public dependencyAnalyzerCmd: string[];
  public logger: Logger;
  public isDebug: boolean;
  public enableDeclgenEts2Ts: boolean;
  public declgenV1OutPath: string | undefined;
  public declgenV2OutPath: string | undefined;
  public declgenBridgeCodePath: string | undefined;
  public hasMainModule: boolean;
  public abcFiles: Set<string>;
  public hashCacheFile: string;
  public hashCache: Record<string, string>;
  public isCacheFileExists: boolean;
  public dependencyFileMap: DependencyFileConfig | null;
  public isBuildConfigModified: boolean | undefined;
  public byteCodeHar: boolean;
  public isHybrid: boolean;

  constructor(buildConfig: BuildConfig) {
    this.buildConfig = buildConfig;
    this.entryFiles = new Set<string>(buildConfig.compileFiles as string[]);
    this.compileFiles = new Map<string, CompileFileInfo>();
    this.outputDir = buildConfig.loaderOutPath as string;
    this.cacheDir = buildConfig.cachePath as string;
    this.pandaSdkPath = buildConfig.pandaSdkPath as string;
    this.buildSdkPath = buildConfig.buildSdkPath as string;
    this.packageName = buildConfig.packageName as string;
    this.sourceRoots = buildConfig.sourceRoots as string[];
    this.moduleRootPath = buildConfig.moduleRootPath as string;
    this.moduleType = buildConfig.moduleType as string;
    this.dependentModuleList = buildConfig.dependentModuleList;
    this.moduleInfos = new Map<string, ModuleInfo>();
    this.mergedAbcFile = path.resolve(this.outputDir, MERGED_ABC_FILE);
    this.dependencyJsonFile = path.resolve(this.cacheDir, DEPENDENCY_JSON_FILE);
    this.abcLinkerCmd = ['"' + this.buildConfig.abcLinkerPath + '"'];
    this.dependencyAnalyzerCmd = ['"' + this.buildConfig.dependencyAnalyzerPath + '"'];
    this.logger = Logger.getInstance();
    this.isDebug = buildConfig.buildMode as string === BUILD_MODE.DEBUG;
    this.enableDeclgenEts2Ts = buildConfig.enableDeclgenEts2Ts as boolean;
    this.declgenV1OutPath = buildConfig.declgenV1OutPath as string | undefined;
    this.declgenV2OutPath = buildConfig.declgenV2OutPath as string | undefined;
    this.declgenBridgeCodePath = buildConfig.declgenBridgeCodePath as string | undefined;
    this.hasMainModule = buildConfig.hasMainModule;
    this.abcFiles = new Set<string>();
    this.hashCacheFile = path.join(this.cacheDir, 'hash_cache.json');
    this.hashCache = this.loadHashCache();
    this.isCacheFileExists = fs.existsSync(this.hashCacheFile);
    this.dependencyFileMap = null;
    this.isBuildConfigModified = buildConfig.isBuildConfigModified as boolean | undefined;
    this.byteCodeHar = buildConfig.byteCodeHar as boolean;
    this.isHybrid = isHybrid(buildConfig);
  }

  public declgen(fileInfo: CompileFileInfo): void {
    const source = fs.readFileSync(fileInfo.filePath, 'utf8');
    const moduleInfo: ModuleInfo = this.moduleInfos.get(fileInfo.packageName)!;
    const filePathFromModuleRoot: string = path.relative(moduleInfo.moduleRootPath, fileInfo.filePath);
    const declEtsOutputPath: string = changeDeclgenFileExtension(
      path.join(moduleInfo.declgenV1OutPath as string, moduleInfo.packageName, filePathFromModuleRoot),
      DECL_ETS_SUFFIX
    );
    const etsOutputPath: string = changeDeclgenFileExtension(
      path.join(moduleInfo.declgenBridgeCodePath as string, moduleInfo.packageName, filePathFromModuleRoot),
      TS_SUFFIX
    );
    ensurePathExists(declEtsOutputPath);
    ensurePathExists(etsOutputPath);
    const arktsGlobal: ArkTSGlobal = this.buildConfig.arktsGlobal;
    const arkts: ArkTS = this.buildConfig.arkts;
    let errorStatus = false;
    try {
      const staticRecordPath = path.join(
        moduleInfo.declgenV1OutPath as string,
        STATIC_RECORD_FILE
      )
      const declEtsOutputDir = path.dirname(declEtsOutputPath);
      const staticRecordRelativePath = changeFileExtension(
        path.relative(declEtsOutputDir, staticRecordPath).replaceAll(/\\/g, '\/'),
        '',
        DECL_TS_SUFFIX
      );
      createFileIfNotExists(staticRecordPath, STATIC_RECORD_FILE_CONTENT);

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
        false,
        staticRecordRelativePath
      ); // Generate 1.0 declaration files & 1.0 glue code
      this.logger.printInfo('declaration files generated');
    } catch (error) {
      errorStatus = true;
      if (error instanceof Error) {
        const logData: LogData = LogDataFactory.newInstance(
          ErrorCode.BUILDSYSTEM_DECLGEN_FAIL,
          'Generate declaration files failed.',
          error.message,
          fileInfo.filePath
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

    const ets2pandaCmd: string[] = [
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

    const arktsGlobal = this.buildConfig.arktsGlobal;
    const arkts = this.buildConfig.arkts;
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
          error.message,
          fileInfo.filePath
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

  public compileMultiFiles(filePaths: string[], moduleInfo: ModuleInfo): void {
    let ets2pandaCmd: string[] = [
      '_',
      '--extension',
      'ets',
      '--arktsconfig',
      moduleInfo.arktsConfigFile,
      '--output',
      path.resolve(this.outputDir, MERGED_ABC_FILE),
      '--simultaneous'
    ];
    ensurePathExists(path.resolve(this.outputDir, MERGED_ABC_FILE));
    if (this.isDebug) {
      ets2pandaCmd.push('--debug-info');
    }
    ets2pandaCmd.push(this.buildConfig.compileFiles[0]);
    this.logger.printInfo('ets2pandaCmd: ' + ets2pandaCmd.join(' '));

    let arktsGlobal = this.buildConfig.arktsGlobal;
    let arkts = this.buildConfig.arkts;
    let errorStatus = false;
    try {
      arktsGlobal.config = arkts.Config.create(ets2pandaCmd).peer;
      //@ts-ignore
      arktsGlobal.compilerContext = arkts.Context.createContextGenerateAbcForExternalSourceFiles(this.buildConfig.compileFiles);;
      PluginDriver.getInstance().getPluginContext().setArkTSProgram(arktsGlobal.compilerContext.program);

      arkts.proceedToState(arkts.Es2pandaContextState.ES2PANDA_STATE_PARSED, arktsGlobal.compilerContext.peer);
      this.logger.printInfo('es2panda proceedToState parsed');
      let ast = arkts.EtsScript.fromContext();
      PluginDriver.getInstance().getPluginContext().setArkTSAst(ast);
      PluginDriver.getInstance().runPluginHook(PluginHook.PARSED);
      this.logger.printInfo('plugin parsed finished');

      arkts.proceedToState(arkts.Es2pandaContextState.ES2PANDA_STATE_CHECKED, arktsGlobal.compilerContext.peer);
      this.logger.printInfo('es2panda proceedToState checked');

      ast = arkts.EtsScript.fromContext();
      PluginDriver.getInstance().getPluginContext().setArkTSAst(ast);
      PluginDriver.getInstance().runPluginHook(PluginHook.CHECKED);
      this.logger.printInfo('plugin checked finished');

      arkts.proceedToState(arkts.Es2pandaContextState.ES2PANDA_STATE_BIN_GENERATED, arktsGlobal.compilerContext.peer);
      this.logger.printInfo('es2panda bin generated');
    } catch (error) {
      errorStatus = true;
      throw error;
    } finally {
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
    this.collectDependencyModules(moduleInfo.packageName, moduleInfo, dynamicDepModules, staticDepModules);

    if (moduleInfo.isMainModule) {
      this.moduleInfos.forEach((module: ModuleInfo, packageName: string) => {
        if (module.isMainModule) {
          return;
        }
        this.collectDependencyModules(packageName, module, dynamicDepModules, staticDepModules);
      });
      if (moduleInfo.language === LANGUAGE_VERSION.ARKTS_HYBRID) {
        dynamicDepModules.set(moduleInfo.packageName, moduleInfo);
      }
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
          this.collectDependencyModules(packageName, depModuleInfo, dynamicDepModules, staticDepModules);
        }
      });
    }
    return [dynamicDepModules, staticDepModules];
  }

  private collectDependencyModules(
    packageName: string,
    module: ModuleInfo,
    dynamicDepModules: Map<string, ModuleInfo>,
    staticDepModules: Map<string, ModuleInfo>
  ): void {
    if (module.language === LANGUAGE_VERSION.ARKTS_1_2) {
      staticDepModules.set(packageName, module);
    } else if (module.language === LANGUAGE_VERSION.ARKTS_1_1) {
      dynamicDepModules.set(packageName, module);
    } else if (module.language === LANGUAGE_VERSION.ARKTS_HYBRID) {
      staticDepModules.set(packageName, module);
      dynamicDepModules.set(packageName, module);
    }
  }

  protected generateArkTSConfigForModules(): void {
    this.moduleInfos.forEach((moduleInfo: ModuleInfo, moduleRootPath: string) => {
      ArkTSConfigGenerator.getInstance(this.buildConfig, this.moduleInfos)
        .writeArkTSConfigFile(moduleInfo, this.enableDeclgenEts2Ts, this.buildConfig);
    });
  }

  private collectDepModuleInfos(): void {
    this.moduleInfos.forEach((moduleInfo: ModuleInfo) => {
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
    const mainModuleInfo: ModuleInfo = this.getMainModuleInfo();
    this.moduleInfos.set(this.packageName, mainModuleInfo);
    this.dependentModuleList.forEach((module: DependentModuleConfig) => {
      if (!module.packageName || !module.modulePath || !module.sourceRoots || !module.entryFile) {
        const logData: LogData = LogDataFactory.newInstance(
          ErrorCode.BUILDSYSTEM_DEPENDENT_MODULE_INFO_NOT_CORRECT_FAIL,
          'Dependent module info from hvigor is not correct.'
        );
        this.logger.printError(logData);
      }
      if (this.moduleInfos.has(module.packageName)) {
        return;
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
        declgenV2OutPath: module.declgenV2OutPath,
        declgenBridgeCodePath: module.declgenBridgeCodePath,
        language: module.language,
        declFilesPath: module.declFilesPath,
        byteCodeHar: module.byteCodeHar,
        dependencies: module.dependencies
      };
      this.moduleInfos.set(module.packageName, moduleInfo);
    });
    this.collectDepModuleInfos();
  }

  protected getMainModuleInfo(): ModuleInfo {
    const mainModuleInfo = this.dependentModuleList.find((module: DependentModuleConfig) => module.packageName === this.packageName);
    return {
      isMainModule: this.hasMainModule,
      packageName: mainModuleInfo?.packageName ?? this.packageName,
      moduleRootPath: mainModuleInfo?.modulePath ?? this.moduleRootPath,
      moduleType: mainModuleInfo?.moduleType ?? this.moduleType,
      sourceRoots: this.sourceRoots,
      entryFile: '',
      arktsConfigFile: path.resolve(this.cacheDir, this.packageName, ARKTSCONFIG_JSON_FILE),
      dynamicDepModuleInfos: new Map<string, ModuleInfo>(),
      staticDepModuleInfos: new Map<string, ModuleInfo>(),
      compileFileInfos: [],
      declgenV1OutPath: mainModuleInfo?.declgenV1OutPath ?? this.declgenV1OutPath,
      declgenV2OutPath: mainModuleInfo?.declgenV2OutPath ?? this.declgenV2OutPath,
      declgenBridgeCodePath: mainModuleInfo?.declgenBridgeCodePath ?? this.declgenBridgeCodePath,
      byteCodeHar: this.byteCodeHar,
      language: mainModuleInfo?.language ?? LANGUAGE_VERSION.ARKTS_1_2,
      declFilesPath: mainModuleInfo?.declFilesPath,
    };
  }

  private loadHashCache(): Record<string, string> {
    try {
      if (!fs.existsSync(this.hashCacheFile)) {
        return {};
      }

      const cacheContent: string = fs.readFileSync(this.hashCacheFile, 'utf-8');
      const cacheData: Record<string, string> = JSON.parse(cacheContent);
      const filteredCache: Record<string, string> = Object.fromEntries(
        Object.entries(cacheData).filter(([file]) => this.entryFiles.has(file))
      );
      return filteredCache;
    } catch (error) {
      if (error instanceof Error) {
        const logData: LogData = LogDataFactory.newInstance(
          ErrorCode.BUILDSYSTEM_LOAD_HASH_CACHE_FAIL,
          'Failed to load hash cache.',
          error.message
        );
        this.logger.printError(logData);
      }
      return {};
    }
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
        if (cachedHash && cachedHash === currentHash) {
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
      for (const [_, moduleInfo] of this.moduleInfos) {
        if (!file.startsWith(moduleInfo.moduleRootPath)) {
          continue;
        }

        hasModule = true;
        const filePathFromModuleRoot = path.relative(moduleInfo.moduleRootPath, file);
        const filePathInCache = path.join(this.cacheDir, moduleInfo.packageName, filePathFromModuleRoot);
        const abcFilePath = path.resolve(changeFileExtension(filePathInCache, ABC_SUFFIX));

        this.abcFiles.add(abcFilePath);
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
        // For the 1.1 declaration file referenced in dynamicPaths, if a path is detected as non-existent, it will be skipped.
        const isFileExist = fs.existsSync(dependant);
        if (!isFileExist) {
          return;
        }
        if (!compileFiles.has(dependant) && !processed.has(dependant)) {
          queue.push(dependant);
        }
        compileFiles.add(dependant);
      });
    }

    compileFiles.forEach((file: string) => {
      let hasModule = false;
      for (const [_, moduleInfo] of this.moduleInfos) {
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
    if (!this.isBuildConfigModified && this.isCacheFileExists && !this.enableDeclgenEts2Ts && !this.isHybrid) {
      this.collectDependentCompileFiles();
      return;
    }
    this.entryFiles.forEach((file: string) => {
      for (const [_, moduleInfo] of this.moduleInfos) {
        const relativePath = path.relative(moduleInfo.moduleRootPath, file);
        if (relativePath.startsWith('..') || path.isAbsolute(relativePath)) {
          continue;
        }
        const filePathFromModuleRoot: string = path.relative(moduleInfo.moduleRootPath, file);
        const filePathInCache: string = path.join(this.cacheDir, moduleInfo.packageName, filePathFromModuleRoot);
        const abcFilePath: string = path.resolve(changeFileExtension(filePathInCache, ABC_SUFFIX));
        this.abcFiles.add(abcFilePath);
        if (!this.isBuildConfigModified && this.shouldSkipFile(file, moduleInfo, filePathFromModuleRoot, abcFilePath)) {
          return;
        }
        this.hashCache[file] = getFileHash(file);
        const fileInfo: CompileFileInfo = {
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
    this.compileFiles.forEach((fileInfo: CompileFileInfo, _: string) => {
      compilePromises.push(new Promise<void>((resolve) => {
        this.declgen(fileInfo);
        resolve();
      }));
    });
    await Promise.all(compilePromises);
  }

  public async run(): Promise<void> {
    this.generateModuleInfos();

    let moduleToFile = new Map<string, string[]>();
    this.compileFiles.forEach((fileInfo: CompileFileInfo, _: string) => {
      if (!moduleToFile.has(fileInfo.packageName)) {
        moduleToFile.set(fileInfo.packageName, []);
      }
      moduleToFile.get(fileInfo.packageName)?.push(fileInfo.filePath);
    });
    try {
      //@ts-ignore
      this.compileMultiFiles([], this.moduleInfos.get(this.packageName));
    } catch (error) {
      if (error instanceof Error) {
        const logData: LogData = LogDataFactory.newInstance(
          ErrorCode.BUILDSYSTEM_COMPILE_ABC_FAIL,
          'Compile abc files failed.',
          error.message
        );
        this.logger.printErrorAndExit(logData);
      }
    }
  }

  private terminateAllWorkers(): void {
    Object.values(cluster.workers || {}).forEach(worker => {
      worker?.kill();
    });
  };

  public generatedependencyFileMap(): void {
    if (this.isBuildConfigModified || !this.isCacheFileExists || this.enableDeclgenEts2Ts || this.isHybrid) {
      return;
    }
    const dependencyInputFile: string = path.join(this.cacheDir, DEPENDENCY_INPUT_FILE);
    let dependencyInputContent: string = '';
    this.entryFiles.forEach((entryFile: string) => {
      dependencyInputContent += entryFile + os.EOL;
    });
    fs.writeFileSync(dependencyInputFile, dependencyInputContent);

    this.dependencyAnalyzerCmd.push('@' + '"' + dependencyInputFile + '"');
    for (const [_, module] of this.moduleInfos) {
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

  public async runParallel(): Promise<void> {
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
      worker.send({ taskList: taskChunk, buildConfig: serializableConfig, moduleInfos: moduleInfosArray });

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
      isDeclFile?: boolean;
    }) => {
      if (message.success) {
        return;
      }
      if (message.isDeclFile) {
        this.logger.printError(LogDataFactory.newInstance(
          ErrorCode.BUILDSYSTEM_DECLGEN_FAIL,
          'Generate declaration files failed in worker.',
          message.error || 'Unknown error',
          message.filePath
        ));
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
}
