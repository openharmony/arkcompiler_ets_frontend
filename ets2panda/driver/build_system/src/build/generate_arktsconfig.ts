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

import {
  Logger,
  LogData,
  LogDataFactory
} from '../logger';
import {
  ErrorCode
} from '../error_code';
import {
  changeFileExtension,
  ensurePathExists,
  getInteropFilePathByApi,
  getOhmurlByApi,
  isSubPathOf,
  safeRealpath,
  toUnixPath
} from '../utils';
import {
  AliasConfig,
  BuildConfig,
  DependencyItem,
  DynamicFileContext,
  ModuleInfo,
} from '../types';
import {
  COMPONENT,
  KITS,
  LANGUAGE_VERSION,
  SYSTEM_SDK_PATH_FROM_SDK,
  sdkConfigPrefix,
} from '../pre_define';

interface ArkTSConfigObject {
  compilerOptions: {
    package: string,
    baseUrl: string,
    paths: Record<string, string[]>;
    entry?: string;
    dependencies: Record<string, DependencyItem>;
    useEmptyPackage?: boolean;
  }
};

export class ArkTSConfigGenerator {
  private static instance: ArkTSConfigGenerator | undefined;
  private stdlibStdPath: string;
  private stdlibEscompatPath: string;
  private systemSdkPath: string;
  private externalApiPaths: string[];

  private moduleInfos: Map<string, ModuleInfo>;
  private pathSection: Record<string, string[]>;

  private logger: Logger;
  private aliasConfig: Map<string, Map<string, AliasConfig>>;
  private dynamicSDKPaths: Set<string>;

  private constructor(buildConfig: BuildConfig, moduleInfos: Map<string, ModuleInfo>) {
    this.logger = Logger.getInstance();
    const realPandaSdkPath = safeRealpath(buildConfig.pandaSdkPath!!, this.logger);
    const realBuildSdkPath = safeRealpath(buildConfig.buildSdkPath, this.logger);
    const realPandaStdlibPath = buildConfig.pandaStdlibPath ?? path.resolve(realPandaSdkPath, 'lib', 'stdlib');
    this.stdlibStdPath = path.resolve(realPandaStdlibPath, 'std');
    this.stdlibEscompatPath = path.resolve(realPandaStdlibPath, 'escompat');
    this.systemSdkPath = path.resolve(realBuildSdkPath, SYSTEM_SDK_PATH_FROM_SDK);
    this.externalApiPaths = buildConfig.externalApiPaths;

    this.moduleInfos = moduleInfos;
    this.pathSection = {};
    this.aliasConfig = buildConfig.aliasConfig;
    this.dynamicSDKPaths = buildConfig.interopSDKPaths;
  }

  public static getInstance(buildConfig?: BuildConfig, moduleInfos?: Map<string, ModuleInfo>): ArkTSConfigGenerator {
    if (!ArkTSConfigGenerator.instance) {
      if (!buildConfig || !moduleInfos) {
        throw new Error(
          'buildConfig and moduleInfos is required for the first instantiation of ArkTSConfigGenerator.');
      }
      ArkTSConfigGenerator.instance = new ArkTSConfigGenerator(buildConfig, moduleInfos);
    }
    return ArkTSConfigGenerator.instance;
  }

  public static destroyInstance(): void {
    ArkTSConfigGenerator.instance = undefined;
  }

  private generateSystemSdkPathSection(pathSection: Record<string, string[]>): void {
    function traverse(currentDir: string, relativePath: string = '', isExcludedDir: boolean = false, allowedExtensions: string[] = ['.d.ets']): void {
      const items = fs.readdirSync(currentDir);
      for (const item of items) {
        const itemPath = path.join(currentDir, item);
        const stat = fs.statSync(itemPath);
        const isAllowedFile = allowedExtensions.some(ext => item.endsWith(ext));
        if (stat.isFile() && !isAllowedFile) {
          continue;
        }

        if (stat.isFile()) {
          const basename = path.basename(item, '.d.ets');
          const key = isExcludedDir ? basename : (relativePath ? `${relativePath}.${basename}` : basename);
          pathSection[key] = [changeFileExtension(itemPath, '', '.d.ets')];
        }
        if (stat.isDirectory()) {
          // For files under api dir excluding arkui/runtime-api dir,
          // fill path section with `"pathFromApi.subdir.fileName" = [${absolute_path_to_file}]`;
          // For @koalaui files under arkui/runtime-api dir,
          // fill path section with `"fileName" = [${absolute_path_to_file}]`.
          const isCurrentDirExcluded = path.basename(currentDir) === 'arkui' && item === 'runtime-api';
          const newRelativePath = isCurrentDirExcluded ? '' : (relativePath ? `${relativePath}.${item}` : item);
          traverse(path.resolve(currentDir, item), newRelativePath, isCurrentDirExcluded || isExcludedDir);
        }
      }
    }

    if (this.externalApiPaths && this.externalApiPaths.length !== 0) {
      this.externalApiPaths.forEach((sdkPath: string) => {
        fs.existsSync(sdkPath) ? traverse(sdkPath) : this.logger.printWarn(`sdk path ${sdkPath} not exist.`);
      });
    } else {
      // Search openharmony sdk only, we keep them for ci compatibility.
      let apiPath: string = path.resolve(this.systemSdkPath, 'api');
      fs.existsSync(apiPath) ? traverse(apiPath) : this.logger.printWarn(`sdk path ${apiPath} not exist.`);

      let arktsPath: string = path.resolve(this.systemSdkPath, 'arkts');
      fs.existsSync(arktsPath) ? traverse(arktsPath) : this.logger.printWarn(`sdk path ${arktsPath} not exist.`);

      let kitsPath: string = path.resolve(this.systemSdkPath, 'kits');
      fs.existsSync(kitsPath) ? traverse(kitsPath) : this.logger.printWarn(`sdk path ${kitsPath} not exist.`);
    }
  }

  private getPathSection(moduleInfo: ModuleInfo): Record<string, string[]> {
    if (Object.keys(this.pathSection).length !== 0) {
      return this.pathSection;
    }

    this.pathSection.std = [this.stdlibStdPath];
    this.pathSection.escompat = [this.stdlibEscompatPath];

    this.generateSystemSdkPathSection(this.pathSection);

    this.moduleInfos.forEach((moduleInfo: ModuleInfo, packageName: string) => {
      if (moduleInfo.language !== LANGUAGE_VERSION.ARKTS_1_2 && moduleInfo.language !== LANGUAGE_VERSION.ARKTS_HYBRID) {
        return;
      }
      if (!moduleInfo.entryFile) {
        return;
      }
      this.handleEntryFile(moduleInfo);
    });
    return this.pathSection;
  }

  private handleEntryFile(moduleInfo: ModuleInfo): void {
    try {
      const stat = fs.statSync(moduleInfo.entryFile);
      if (!stat.isFile()) {
        return;
      }
      const entryFilePath = moduleInfo.entryFile;
      const firstLine = fs.readFileSync(entryFilePath, 'utf-8').split('\n')[0];
      // If the file is an ArkTS 1.2 implementation, configure the path in pathSection.
      if (moduleInfo.language === LANGUAGE_VERSION.ARKTS_1_2 || moduleInfo.language === LANGUAGE_VERSION.ARKTS_HYBRID && firstLine.includes('use static')) {
        this.pathSection[moduleInfo.packageName] = [
          path.resolve(moduleInfo.moduleRootPath, moduleInfo.sourceRoots[0])
        ];
      }
    } catch (error) {
      const logData: LogData = LogDataFactory.newInstance(
        ErrorCode.BUILDSYSTEM_HANDLE_ENTRY_FILE,
        `Error handle entry file for module ${moduleInfo.packageName}`
      );
      this.logger.printError(logData);
    }
  }

  private getOhmurl(file: string, moduleInfo: ModuleInfo): string {
    let unixFilePath: string = file.replace(/\\/g, '/');
    let ohmurl: string = moduleInfo.packageName + '/' + unixFilePath;
    return changeFileExtension(ohmurl, '');
  }

  private getDependenciesSection(moduleInfo: ModuleInfo, dependenciesection: Record<string, DependencyItem>): void {
    let depModules: Map<string, ModuleInfo> = moduleInfo.dynamicDepModuleInfos;

    depModules.forEach((depModuleInfo: ModuleInfo) => {
      if (!depModuleInfo.declFilesPath || !fs.existsSync(depModuleInfo.declFilesPath)) {
        console.error(`Module ${moduleInfo.packageName} depends on dynamic module ${depModuleInfo.packageName}, but
          decl file not found on path ${depModuleInfo.declFilesPath}`);
        return;
      }
      let declFilesObject = JSON.parse(fs.readFileSync(depModuleInfo.declFilesPath, 'utf-8'));
      Object.keys(declFilesObject.files).forEach((file: string) => {
        let ohmurl: string = this.getOhmurl(file, depModuleInfo);
        dependenciesection[ohmurl] = {
          language: 'js',
          path: declFilesObject.files[file].declPath,
          ohmUrl: declFilesObject.files[file].ohmUrl
        };

        let absFilePath: string = path.resolve(depModuleInfo.moduleRootPath, file);
        let entryFileWithoutExtension: string = changeFileExtension(depModuleInfo.entryFile, '');
        if (absFilePath === entryFileWithoutExtension) {
          dependenciesection[depModuleInfo.packageName] = dependenciesection[ohmurl];
        }
      });
    });
  }

  public writeArkTSConfigFile(
    moduleInfo: ModuleInfo,
    enableDeclgenEts2Ts: boolean,
    buildConfig: BuildConfig
  ): void {
    if (!moduleInfo.sourceRoots || moduleInfo.sourceRoots.length === 0) {
      const logData: LogData = LogDataFactory.newInstance(
        ErrorCode.BUILDSYSTEM_SOURCEROOTS_NOT_SET_FAIL,
        'SourceRoots not set from hvigor.'
      );
      this.logger.printErrorAndExit(logData);
    }
    let pathSection = this.getPathSection(moduleInfo);

    this.getAllFilesToPathSectionForHybrid(moduleInfo, buildConfig);
    let dependenciesection: Record<string, DependencyItem> = {};
    if (!enableDeclgenEts2Ts) {
      this.getDependenciesSection(moduleInfo, dependenciesection);
    }
    this.processAlias(moduleInfo, dependenciesection);
    let baseUrl: string = path.resolve(moduleInfo.moduleRootPath, moduleInfo.sourceRoots[0]);
    if (buildConfig.paths) {
      Object.entries(buildConfig.paths).map(([key, value]) => {
        pathSection[key] = value
      });
    }
    let arktsConfig: ArkTSConfigObject = {
      compilerOptions: {
        package: moduleInfo.packageName,
        baseUrl: baseUrl,
        paths: pathSection,
        entry: moduleInfo.entryFile,
        dependencies: dependenciesection
      }
    };

    if (moduleInfo.entryFile && moduleInfo.language === LANGUAGE_VERSION.ARKTS_HYBRID) {
      const entryFilePath = moduleInfo.entryFile;
      const stat = fs.statSync(entryFilePath);
      if (fs.existsSync(entryFilePath) && stat.isFile()) {
        const firstLine = fs.readFileSync(entryFilePath, 'utf-8').split('\n')[0];
        // If the entryFile is not an ArkTS 1.2 implementation, remove the entry property field.
        if (!firstLine.includes('use static')) {
          delete arktsConfig.compilerOptions.entry;
        }
      }
    }

    if (moduleInfo.frameworkMode) {
      arktsConfig.compilerOptions.useEmptyPackage = moduleInfo.useEmptyPackage;
    }

    ensurePathExists(moduleInfo.arktsConfigFile);
    fs.writeFileSync(moduleInfo.arktsConfigFile, JSON.stringify(arktsConfig, null, 2), 'utf-8');
  }

  private processAlias(moduleInfo: ModuleInfo, dependencySection: Record<string, DependencyItem>): void {
    this.dynamicSDKPaths.forEach(basePath => {
      if(basePath.includes(KITS)){
        return;
      }
      if (!fs.existsSync(basePath)) {
        const logData: LogData = LogDataFactory.newInstance(
          ErrorCode.BUILDSYSTEM_ALIAS_MODULE_PATH_NOT_EXIST,
          `alias module ${basePath} not exist.`
        );
        this.logger.printErrorAndExit(logData);
      }
      if(basePath.includes(COMPONENT)){
        this.traverseDependencies(basePath, '', false, dependencySection,'component/');
      }else{
        this.traverseDependencies(basePath, '', false, dependencySection);
        this.traverseDependencies(basePath, '', false, dependencySection,'dynamic/');
      }
    });

    const aliasForPkg: Map<string, AliasConfig> | undefined = this.aliasConfig?.get(moduleInfo.packageName);

    aliasForPkg?.forEach((aliasConfig, aliasName) => {
      if(aliasConfig.isStatic){
        return;
      }
      if (aliasConfig.originalAPIName.startsWith('@kit')) {
        this.processStaticAlias(aliasName, aliasConfig);
      }else{
        this.processDynamicAlias(aliasName, aliasConfig,dependencySection);
      }
    });
  }

  private traverseDependencies(
    currentDir: string,
    relativePath: string,
    isExcludedDir: boolean,
    dependencySection: Record<string, DependencyItem>,
    prefix: string = ''
  ): void {
    const allowedExtensions = ['.d.ets'];
    const items = fs.readdirSync(currentDir);
  
    for (const item of items) {
      const itemPath = path.join(currentDir, item);
      const stat = fs.statSync(itemPath);
  
      if (stat.isFile()) {
        if (this.isAllowedExtension(item, allowedExtensions)) {
          this.processDynamicFile({
            filePath: itemPath,
            fileName: item,
            relativePath,
            isExcludedDir,
            dependencySection,
            prefix
          });
        }
        continue;
      }
  
      if (stat.isDirectory()) {
        const isRuntimeAPI = path.basename(currentDir) === 'arkui' && item === 'runtime-api';
        const newRelativePath = isRuntimeAPI
          ? ''
          : (relativePath ? `${relativePath}/${item}` : item);
  
        this.traverseDependencies(
          path.resolve(currentDir, item),
          newRelativePath,
          isExcludedDir || isRuntimeAPI,
          dependencySection,
          prefix
        );
      }
    }
  }

  private isAllowedExtension(fileName: string, allowedExtensions: string[]): boolean {
    return allowedExtensions.some(ext => fileName.endsWith(ext));
  }

  private isValidAPIFile(fileName: string): boolean {
    const pattern = new RegExp(`^@(${sdkConfigPrefix})\\..+\\.d\\.ets$`, 'i');
    return pattern.test(fileName);
  }
  
  private buildDynamicKey(
    baseName: string,
    relativePath: string,
    isExcludedDir: boolean,
    prefix: string = '',
    separator: string = '.'
  ): string {
    return prefix + (isExcludedDir
      ? baseName
      : (relativePath ? `${relativePath}${separator}${baseName}` : baseName)
    );
  }
  
  private processDynamicFile(ctx: DynamicFileContext): void {
    const {
      filePath,
      fileName,
      relativePath,
      isExcludedDir,
      dependencySection,
      prefix = ''
    } = ctx;
    let separator = '.'
    if (!this.isValidAPIFile(fileName)){
      separator = '/'
    }
    
    const baseName = path.basename(fileName, '.d.ets');
    const normalizedRelativePath = relativePath.replace(/\//g, separator);
    const key = this.buildDynamicKey(baseName, normalizedRelativePath, isExcludedDir, prefix, separator);

    dependencySection[key] = {
      language: 'js',
      path: filePath,
      ohmUrl: getOhmurlByApi(baseName)
    };
  }

  private processStaticAlias(aliasName: string, aliasConfig: AliasConfig) {
    this.pathSection[aliasName] = [getInteropFilePathByApi(aliasConfig.originalAPIName, this.dynamicSDKPaths)];
  }

  private processDynamicAlias(
    aliasName: string,
    aliasConfig: AliasConfig,
    dependencySection: Record<string, DependencyItem>
  ) {
    const originalName = aliasConfig.originalAPIName;
    const declPath = getInteropFilePathByApi(originalName, this.dynamicSDKPaths);
    if (declPath === '') {
      return;
    }
  
    if (!fs.existsSync(declPath)) {
      const logData: LogData = LogDataFactory.newInstance(
        ErrorCode.BUILDSYSTEM_INTEROP_SDK_NOT_FIND,
        `Interop SDK File Not Exist: ${declPath}`
      );
      this.logger.printErrorAndExit(logData);
    }

    const existing = dependencySection[originalName];

    if (existing) {
      existing.alias = Array.from(new Set([...(existing.alias ?? []), aliasName]));
    } else {
      dependencySection[originalName] = {
        language: 'js',
        path: declPath,
        ohmUrl: getOhmurlByApi(originalName),
        alias: [aliasName]
      };
    }
  }

  public getAllFilesToPathSectionForHybrid(
    moduleInfo: ModuleInfo,
    buildConfig: BuildConfig
  ): void {
    if (moduleInfo?.language !== LANGUAGE_VERSION.ARKTS_HYBRID) {
      return;
    }

    const moduleRoot = toUnixPath(moduleInfo.moduleRootPath) + '/';

    for (const file of buildConfig.compileFiles) {
      const unixFilePath = toUnixPath(file);

      if (!isSubPathOf(unixFilePath, moduleRoot)) {
        continue;
      }

      let relativePath = unixFilePath.startsWith(moduleRoot)
        ? unixFilePath.substring(moduleRoot.length)
        : unixFilePath;

      const keyWithoutExtension = relativePath.replace(/\.[^/.]+$/, '');
      this.pathSection[keyWithoutExtension] = [file];
    }
  }  
}
