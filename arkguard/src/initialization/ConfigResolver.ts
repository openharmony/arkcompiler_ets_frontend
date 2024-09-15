/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

import fs from 'fs';
import path from 'path';
import JSON5 from 'json5';

import type * as ts from 'typescript';

import { FileUtils } from '../utils/FileUtils';
import {
  type ReservedNameInfo,
  ApiExtractor,
  containWildcards,
  getMapFromJson,
  performancePrinter,
  PropCollections,
  renameFileNameModule,
  separateUniversalReservedItem,
  wildcardTransformer,
} from '../ArkObfuscator';

import { isDebug, isFileExist, sortAndDeduplicateStringArr, mergeSet, convertSetToArray } from './utils';
import { nameCacheMap, yellow, unobfuscationNamesObj } from './CommonObject';
import { historyUnobfuscatedPropMap } from './Initializer';
import { LocalVariableCollections, UnobfuscationCollections } from '../utils/CommonCollections';
import { INameObfuscationOption } from '../configs/INameObfuscationOption';
import { WhitelistType } from '../utils/TransformUtil';

enum OptionType {
  NONE,
  KEEP,
  KEEP_DTS,
  KEEP_GLOBAL_NAME,
  KEEP_PROPERTY_NAME,
  KEEP_FILE_NAME,
  KEEP_COMMENTS,
  DISABLE_OBFUSCATION,
  ENABLE_PROPERTY_OBFUSCATION,
  ENABLE_STRING_PROPERTY_OBFUSCATION,
  ENABLE_TOPLEVEL_OBFUSCATION,
  ENABLE_FILENAME_OBFUSCATION,
  ENABLE_EXPORT_OBFUSCATION,
  COMPACT,
  REMOVE_LOG,
  REMOVE_COMMENTS,
  PRINT_NAMECACHE,
  PRINT_KEPT_NAMES,
  APPLY_NAMECACHE,
}
export { OptionType as OptionTypeForTest };

type SystemApiContent = {
  ReservedPropertyNames?: string[];
  ReservedGlobalNames?: string[];
  ReservedLocalNames?: string[];
};

/* ObConfig's properties:
 *   ruleOptions: {
 *    enable: boolean
 *    rules: string[]
 *   }
 *   consumerRules: string[]
 *
 * ObfuscationConfig's properties:
 *   selfConfig: ObConfig
 *   dependencies: { libraries: ObConfig[], hars: string[] }
 *   sdkApis: string[]
 *   obfuscationCacheDir: string
 *   exportRulePath: string
 */
class ObOptions {
  disableObfuscation: boolean = false;
  enablePropertyObfuscation: boolean = false;
  enableStringPropertyObfuscation: boolean = false;
  enableToplevelObfuscation: boolean = false;
  enableFileNameObfuscation: boolean = false;
  enableExportObfuscation: boolean = false;
  printKeptNames: boolean = false;
  removeComments: boolean = false;
  compact: boolean = false;
  removeLog: boolean = false;
  printNameCache: string = '';
  printKeptNamesPath: string = '';
  applyNameCache: string = '';

  merge(other: ObOptions): void {
    this.disableObfuscation = this.disableObfuscation || other.disableObfuscation;
    this.enablePropertyObfuscation = this.enablePropertyObfuscation || other.enablePropertyObfuscation;
    this.enableToplevelObfuscation = this.enableToplevelObfuscation || other.enableToplevelObfuscation;
    this.enableStringPropertyObfuscation =
      this.enableStringPropertyObfuscation || other.enableStringPropertyObfuscation;
    this.removeComments = this.removeComments || other.removeComments;
    this.compact = this.compact || other.compact;
    this.removeLog = this.removeLog || other.removeLog;
    this.enableFileNameObfuscation = this.enableFileNameObfuscation || other.enableFileNameObfuscation;
    this.enableExportObfuscation = this.enableExportObfuscation || other.enableExportObfuscation;
    if (other.printNameCache.length > 0) {
      this.printNameCache = other.printNameCache;
    }
    if (other.printKeptNamesPath.length > 0) {
      this.printKeptNamesPath = other.printKeptNamesPath;
    }
    if (other.applyNameCache.length > 0) {
      this.applyNameCache = other.applyNameCache;
    }
  }
}
export const ObOptionsForTest = ObOptions;

export class MergedConfig {
  options: ObOptions = new ObOptions();
  reservedPropertyNames: string[] = [];
  reservedGlobalNames: string[] = [];
  reservedNames: string[] = [];
  reservedFileNames: string[] = [];
  keepComments: string[] = [];
  keepSourceOfPaths: string[] = []; // The file path or folder path configured by the developer.
  universalReservedPropertyNames: RegExp[] = []; // Support reserved property names contain wildcards.
  universalReservedGlobalNames: RegExp[] = []; // Support reserved global names contain wildcards.
  keepUniversalPaths: RegExp[] = []; // Support reserved paths contain wildcards.
  excludeUniversalPaths: RegExp[] = []; // Support excluded paths contain wildcards.
  excludePathSet: Set<string> = new Set();

  merge(other: MergedConfig): void {
    this.options.merge(other.options);
    this.reservedPropertyNames.push(...other.reservedPropertyNames);
    this.reservedGlobalNames.push(...other.reservedGlobalNames);
    this.reservedFileNames.push(...other.reservedFileNames);
    this.keepComments.push(...other.keepComments);
    this.keepSourceOfPaths.push(...other.keepSourceOfPaths);
    this.keepUniversalPaths.push(...other.keepUniversalPaths);
    this.excludeUniversalPaths.push(...other.excludeUniversalPaths);
    other.excludePathSet.forEach((excludePath) => {
      this.excludePathSet.add(excludePath);
    });
  }

  sortAndDeduplicate(): void {
    this.reservedPropertyNames = sortAndDeduplicateStringArr(this.reservedPropertyNames);
    this.reservedGlobalNames = sortAndDeduplicateStringArr(this.reservedGlobalNames);
    this.reservedFileNames = sortAndDeduplicateStringArr(this.reservedFileNames);
    this.keepComments = sortAndDeduplicateStringArr(this.keepComments);
    this.keepSourceOfPaths = sortAndDeduplicateStringArr(this.keepSourceOfPaths);
  }

  serializeMergedConfig(): string {
    let resultStr: string = '';
    const keys = Object.keys(this.options);
    for (const key of keys) {
      // skip the export of some switches.
      if (this.options[key] === true && ObConfigResolver.exportedSwitchMap.has(String(key))) {
        resultStr += ObConfigResolver.exportedSwitchMap.get(String(key)) + '\n';
      }
    }

    if (this.reservedGlobalNames.length > 0) {
      resultStr += ObConfigResolver.KEEP_GLOBAL_NAME + '\n';
      this.reservedGlobalNames.forEach((item) => {
        resultStr += item + '\n';
      });
    }
    if (this.reservedPropertyNames.length > 0) {
      resultStr += ObConfigResolver.KEEP_PROPERTY_NAME + '\n';
      this.reservedPropertyNames.forEach((item) => {
        resultStr += item + '\n';
      });
    }
    return resultStr;
  }
}

export class ObConfigResolver {
  sourceObConfig: any;
  logger: any;
  isHarCompiled: boolean | undefined;
  isTerser: boolean;

  constructor(projectConfig: any, logger: any, isTerser?: boolean) {
    this.sourceObConfig = projectConfig.obfuscationOptions;
    this.logger = logger;
    this.isHarCompiled = projectConfig.compileHar;
    this.isTerser = isTerser;
  }

  public resolveObfuscationConfigs(): MergedConfig {
    let sourceObConfig = this.sourceObConfig;
    if (!sourceObConfig) {
      return new MergedConfig();
    }
    let enableObfuscation: boolean = sourceObConfig.selfConfig.ruleOptions.enable;

    let selfConfig: MergedConfig = new MergedConfig();
    if (enableObfuscation) {
      this.getSelfConfigs(selfConfig);
      enableObfuscation = !selfConfig.options.disableObfuscation;
    } else {
      selfConfig.options.disableObfuscation = true;
    }

    let needConsumerConfigs: boolean =
      this.isHarCompiled &&
      sourceObConfig.selfConfig.consumerRules &&
      sourceObConfig.selfConfig.consumerRules.length > 0;
    let needDependencyConfigs: boolean = enableObfuscation || needConsumerConfigs;

    let dependencyConfigs: MergedConfig = new MergedConfig();
    const dependencyMaxLength: number = Math.max(
      sourceObConfig.dependencies.libraries.length,
      sourceObConfig.dependencies.hars.length,
    );
    if (needDependencyConfigs && dependencyMaxLength > 0) {
      dependencyConfigs = new MergedConfig();
      this.getDependencyConfigs(sourceObConfig, dependencyConfigs);
      enableObfuscation = enableObfuscation && !dependencyConfigs.options.disableObfuscation;
    }
    const mergedConfigs: MergedConfig = this.getMergedConfigs(selfConfig, dependencyConfigs);
    UnobfuscationCollections.printKeptName = mergedConfigs.options.printKeptNames;
    this.handleReservedArray(mergedConfigs);

    let needKeepSystemApi =
      enableObfuscation &&
      (mergedConfigs.options.enablePropertyObfuscation ||
        (mergedConfigs.options.enableExportObfuscation && mergedConfigs.options.enableToplevelObfuscation));

    if (needKeepSystemApi && sourceObConfig.obfuscationCacheDir) {
      const systemApiCachePath: string = path.join(sourceObConfig.obfuscationCacheDir, 'systemApiCache.json');
      if (isFileExist(systemApiCachePath)) {
        this.getSystemApiConfigsByCache(systemApiCachePath);
      } else {
        performancePrinter?.iniPrinter?.startEvent('  Scan system api');
        this.getSystemApiCache(mergedConfigs, systemApiCachePath);
        performancePrinter?.iniPrinter?.endEvent('  Scan system api');
      }
    }

    if (needConsumerConfigs) {
      let selfConsumerConfig = new MergedConfig();
      this.getSelfConsumerConfig(selfConsumerConfig);
      this.genConsumerConfigFiles(sourceObConfig, selfConsumerConfig, dependencyConfigs);
    }
    return mergedConfigs;
  }

  private getSelfConfigs(selfConfigs: MergedConfig): void {
    if (this.sourceObConfig.selfConfig.ruleOptions.rules) {
      const configPaths: string[] = this.sourceObConfig.selfConfig.ruleOptions.rules;
      for (const path of configPaths) {
        this.getConfigByPath(path, selfConfigs);
      }
    }
  }

  public getSelfConfigsForTest(selfConfigs: MergedConfig): void {
    return this.getSelfConfigs(selfConfigs);
  }

  private getConfigByPath(path: string, configs: MergedConfig): void {
    let fileContent = undefined;
    try {
      fileContent = fs.readFileSync(path, 'utf-8');
    } catch (err) {
      this.logger.error(`Failed to open ${path}. Error message: ${err}`);
      throw err;
    }
    this.handleConfigContent(fileContent, configs, path);
  }
  
  public getConfigByPathForTest(path: string, configs: MergedConfig): void {
    return this.getConfigByPath(path, configs);
  }

  private handleReservedArray(mergedConfigs: MergedConfig): void {
    if (mergedConfigs.options.enablePropertyObfuscation && mergedConfigs.reservedPropertyNames) {
      const propertyReservedInfo: ReservedNameInfo = separateUniversalReservedItem(mergedConfigs.reservedPropertyNames);
      mergedConfigs.universalReservedPropertyNames = propertyReservedInfo.universalReservedArray;
      mergedConfigs.reservedPropertyNames = propertyReservedInfo.specificReservedArray;
    }

    if (mergedConfigs.options.enableToplevelObfuscation && mergedConfigs.reservedGlobalNames) {
      const globalReservedInfo: ReservedNameInfo = separateUniversalReservedItem(mergedConfigs.reservedGlobalNames);
      mergedConfigs.universalReservedGlobalNames = globalReservedInfo.universalReservedArray;
      mergedConfigs.reservedGlobalNames = globalReservedInfo.specificReservedArray;
    }
  }

  public handleReservedArrayForTest(mergedConfigs: MergedConfig): void {
    return this.handleReservedArray(mergedConfigs);
  }

  // obfuscation options
  static readonly KEEP = '-keep';
  static readonly KEEP_DTS = '-keep-dts';
  static readonly KEEP_GLOBAL_NAME = '-keep-global-name';
  static readonly KEEP_PROPERTY_NAME = '-keep-property-name';
  static readonly KEEP_FILE_NAME = '-keep-file-name';
  static readonly KEEP_COMMENTS = '-keep-comments';
  static readonly DISABLE_OBFUSCATION = '-disable-obfuscation';
  static readonly ENABLE_PROPERTY_OBFUSCATION = '-enable-property-obfuscation';
  static readonly ENABLE_STRING_PROPERTY_OBFUSCATION = '-enable-string-property-obfuscation';
  static readonly ENABLE_TOPLEVEL_OBFUSCATION = '-enable-toplevel-obfuscation';
  static readonly ENABLE_FILENAME_OBFUSCATION = '-enable-filename-obfuscation';
  static readonly ENABLE_EXPORT_OBFUSCATION = '-enable-export-obfuscation';
  static readonly REMOVE_COMMENTS = '-remove-comments';
  static readonly COMPACT = '-compact';
  static readonly REMOVE_LOG = '-remove-log';
  static readonly PRINT_NAMECACHE = '-print-namecache';
  static readonly PRINT_KEPT_NAMES = '-print-kept-names';
  static readonly APPLY_NAMECACHE = '-apply-namecache';

  // renameFileName, printNameCache, applyNameCache, removeComments and keepComments won't be reserved in obfuscation.txt file.
  static exportedSwitchMap: Map<string, string> = new Map([
    ['disableObfuscation', ObConfigResolver.KEEP_DTS],
    ['enablePropertyObfuscation', ObConfigResolver.ENABLE_PROPERTY_OBFUSCATION],
    ['enableStringPropertyObfuscation', ObConfigResolver.ENABLE_STRING_PROPERTY_OBFUSCATION],
    ['enableToplevelObfuscation', ObConfigResolver.ENABLE_TOPLEVEL_OBFUSCATION],
    ['compact', ObConfigResolver.COMPACT],
    ['removeLog', ObConfigResolver.REMOVE_LOG],
  ]);

  private getTokenType(token: string): OptionType {
    switch (token) {
      case ObConfigResolver.KEEP_DTS:
        return OptionType.KEEP_DTS;
      case ObConfigResolver.KEEP_GLOBAL_NAME:
        return OptionType.KEEP_GLOBAL_NAME;
      case ObConfigResolver.KEEP_PROPERTY_NAME:
        return OptionType.KEEP_PROPERTY_NAME;
      case ObConfigResolver.KEEP_FILE_NAME:
        return OptionType.KEEP_FILE_NAME;
      case ObConfigResolver.KEEP_COMMENTS:
        return OptionType.KEEP_COMMENTS;
      case ObConfigResolver.DISABLE_OBFUSCATION:
        return OptionType.DISABLE_OBFUSCATION;
      case ObConfigResolver.ENABLE_PROPERTY_OBFUSCATION:
        return OptionType.ENABLE_PROPERTY_OBFUSCATION;
      case ObConfigResolver.ENABLE_STRING_PROPERTY_OBFUSCATION:
        return OptionType.ENABLE_STRING_PROPERTY_OBFUSCATION;
      case ObConfigResolver.ENABLE_TOPLEVEL_OBFUSCATION:
        return OptionType.ENABLE_TOPLEVEL_OBFUSCATION;
      case ObConfigResolver.ENABLE_FILENAME_OBFUSCATION:
        return OptionType.ENABLE_FILENAME_OBFUSCATION;
      case ObConfigResolver.ENABLE_EXPORT_OBFUSCATION:
        return OptionType.ENABLE_EXPORT_OBFUSCATION;
      case ObConfigResolver.REMOVE_COMMENTS:
        return OptionType.REMOVE_COMMENTS;
      case ObConfigResolver.COMPACT:
        return OptionType.COMPACT;
      case ObConfigResolver.REMOVE_LOG:
        return OptionType.REMOVE_LOG;
      case ObConfigResolver.PRINT_NAMECACHE:
        return OptionType.PRINT_NAMECACHE;
      case ObConfigResolver.PRINT_KEPT_NAMES:
        return OptionType.PRINT_KEPT_NAMES;
      case ObConfigResolver.APPLY_NAMECACHE:
        return OptionType.APPLY_NAMECACHE;
      case ObConfigResolver.KEEP:
        return OptionType.KEEP;
      default:
        return OptionType.NONE;
    }
  }

  public getTokenTypeForTest(token: string): OptionType {
    return this.getTokenType(token);
  }

  private handleConfigContent(data: string, configs: MergedConfig, configPath: string): void {
    data = this.removeComments(data);
    const tokens = data.split(/[',', '\t', ' ', '\n', '\r\n']/).filter((item) => item !== '');
    let type: OptionType = OptionType.NONE;
    let tokenType: OptionType;
    let dtsFilePaths: string[] = [];
    let keepConfigs: string[] = [];
    for (let i = 0; i < tokens.length; i++) {
      const token = tokens[i];
      tokenType = this.getTokenType(token);
      // handle switches cases
      switch (tokenType) {
        case OptionType.DISABLE_OBFUSCATION: {
          configs.options.disableObfuscation = true;
          continue;
        }
        case OptionType.ENABLE_PROPERTY_OBFUSCATION: {
          configs.options.enablePropertyObfuscation = true;
          continue;
        }
        case OptionType.ENABLE_STRING_PROPERTY_OBFUSCATION: {
          configs.options.enableStringPropertyObfuscation = true;
          continue;
        }
        case OptionType.ENABLE_TOPLEVEL_OBFUSCATION: {
          configs.options.enableToplevelObfuscation = true;
          continue;
        }
        case OptionType.REMOVE_COMMENTS: {
          configs.options.removeComments = true;
          continue;
        }
        case OptionType.ENABLE_FILENAME_OBFUSCATION: {
          configs.options.enableFileNameObfuscation = true;
          continue;
        }
        case OptionType.ENABLE_EXPORT_OBFUSCATION: {
          configs.options.enableExportObfuscation = true;
          continue;
        }
        case OptionType.COMPACT: {
          configs.options.compact = true;
          continue;
        }
        case OptionType.REMOVE_LOG: {
          configs.options.removeLog = true;
          continue;
        }
        case OptionType.PRINT_KEPT_NAMES: {
          configs.options.printKeptNames = true;
          type = tokenType;
          continue;
        }
        case OptionType.KEEP:
        case OptionType.KEEP_DTS:
        case OptionType.KEEP_GLOBAL_NAME:
        case OptionType.KEEP_PROPERTY_NAME:
        case OptionType.KEEP_FILE_NAME:
        case OptionType.KEEP_COMMENTS:
        case OptionType.PRINT_NAMECACHE:
        case OptionType.APPLY_NAMECACHE:
          type = tokenType;
          continue;
        default: {
          // fall-through
        }
      }
      // handle 'keep' options and 'namecache' options
      switch (type) {
        case OptionType.KEEP: {
          keepConfigs.push(token);
          continue;
        }
        case OptionType.KEEP_DTS: {
          dtsFilePaths.push(token);
          continue;
        }
        case OptionType.KEEP_GLOBAL_NAME: {
          configs.reservedGlobalNames.push(token);
          continue;
        }
        case OptionType.KEEP_PROPERTY_NAME: {
          configs.reservedPropertyNames.push(token);
          continue;
        }
        case OptionType.KEEP_FILE_NAME: {
          configs.reservedFileNames.push(token);
          continue;
        }
        case OptionType.KEEP_COMMENTS: {
          configs.keepComments.push(token);
          continue;
        }
        case OptionType.PRINT_NAMECACHE: {
          configs.options.printNameCache = this.resolvePath(configPath, token);
          type = OptionType.NONE;
          continue;
        }
        case OptionType.PRINT_KEPT_NAMES: {
          configs.options.printKeptNamesPath = this.resolvePath(configPath, token);
          type = OptionType.NONE;
          continue;
        }
        case OptionType.APPLY_NAMECACHE: {
          const absNameCachePath: string = this.resolvePath(configPath, token);
          this.determineNameCachePath(absNameCachePath, configPath);
          configs.options.applyNameCache = absNameCachePath;
          type = OptionType.NONE;
          continue;
        }
        default:
          continue;
      }
    }

    this.resolveDts(dtsFilePaths, configs);
    this.resolveKeepConfig(keepConfigs, configs, configPath);
  }

  public handleConfigContentForTest(data: string, configs: MergedConfig, configPath: string): void {
    return this.handleConfigContent(data, configs, configPath);
  } 
  // get absolute path
  private resolvePath(configPath: string, token: string): string {
    if (path.isAbsolute(token)) {
      return token;
    }
    const configDirectory = path.dirname(configPath);
    return path.resolve(configDirectory, token);
  }

  public resolvePathForTest(configPath: string, token: string): string {
    return this.resolvePath(configPath, token);
  }

  // get names in .d.ts files and add them into reserved list
  private resolveDts(dtsFilePaths: string[], configs: MergedConfig): void {
    ApiExtractor.mPropertySet.clear();
    dtsFilePaths.forEach((token) => {
      ApiExtractor.traverseApiFiles(token, ApiExtractor.ApiType.PROJECT);
    });
    configs.reservedNames = configs.reservedNames.concat([...ApiExtractor.mPropertySet]);
    configs.reservedPropertyNames = configs.reservedPropertyNames.concat([...ApiExtractor.mPropertySet]);
    configs.reservedGlobalNames = configs.reservedGlobalNames.concat([...ApiExtractor.mPropertySet]);
    ApiExtractor.mPropertySet.clear();
  }

  public resolveKeepConfig(keepConfigs: string[], configs: MergedConfig, configPath: string): void {
    for (let keepPath of keepConfigs) {
      let tempAbsPath: string;
      const isExclude: boolean = keepPath.startsWith('!');
      // 1: remove '!'
      tempAbsPath = FileUtils.getAbsPathBaseConfigPath(configPath, isExclude ? keepPath.substring(1) : keepPath);

      // contains '*', '?'
      if (containWildcards(tempAbsPath)) {
        const regexPattern = wildcardTransformer(tempAbsPath, true);
        const regexOperator = new RegExp(`^${regexPattern}$`);
        if (isExclude) {
          // start with '!'
          configs.excludeUniversalPaths.push(regexOperator);
        } else {
          configs.keepUniversalPaths.push(regexOperator);
        }
        continue;
      }

      if (isExclude) {
        // exclude specific path
        configs.excludePathSet.add(tempAbsPath);
        continue;
      }

      if (!fs.existsSync(tempAbsPath)) {
        this.logger.warn(yellow + 'ArkTS: The path of obfuscation \'-keep\' configuration does not exist: ' + keepPath);
        continue;
      }
      tempAbsPath = fs.realpathSync(tempAbsPath);
      configs.keepSourceOfPaths.push(FileUtils.toUnixPath(tempAbsPath));
    }
  }

  // the content from '#' to '\n' are comments
  private removeComments(data: string): string {
    const commentStart = '#';
    const commentEnd = '\n';
    let tmpStr = '';
    let isInComments = false;
    for (let i = 0; i < data.length; i++) {
      if (isInComments) {
        isInComments = data[i] !== commentEnd;
      } else if (data[i] !== commentStart) {
        tmpStr += data[i];
      } else {
        isInComments = true;
      }
    }
    return tmpStr;
  }

  /**
   * systemConfigs includes the API directorys.
   * component directory and pre_define.js file path needs to be concatenated
   * @param systemConfigs
   */
  private getSystemApiCache(systemConfigs: MergedConfig, systemApiCachePath: string): void {
    ApiExtractor.mPropertySet.clear();
    ApiExtractor.mSystemExportSet.clear();

    interface ArkUIWhitelist {
      ReservedPropertyNames: string[]
    }
    let arkUIWhitelist: ArkUIWhitelist = { ReservedPropertyNames: [] };
    const sdkApis: string[] = sortAndDeduplicateStringArr(this.sourceObConfig.sdkApis);
    for (let apiPath of sdkApis) {
      this.getSdkApiCache(apiPath);
      const UIPath: string = path.join(apiPath, '../build-tools/ets-loader/lib/pre_define.js');
      if (fs.existsSync(UIPath)) {
        this.getUIApiCache(UIPath);
      }
      const arkUIWhitelistPath: string = path.join(apiPath, '../build-tools/ets-loader/obfuscateWhiteList.json5');
      if (fs.existsSync(arkUIWhitelistPath)) {
        arkUIWhitelist = JSON5.parse(fs.readFileSync(arkUIWhitelistPath, 'utf-8'));
      }
    }
    let systemApiContent: SystemApiContent = {};

    if (systemConfigs.options.enablePropertyObfuscation) {
      const savedNameAndPropertySet = new Set([...ApiExtractor.mPropertySet, ...arkUIWhitelist.ReservedPropertyNames]);
      UnobfuscationCollections.reservedSdkApiForProp = savedNameAndPropertySet;
      UnobfuscationCollections.reservedSdkApiForLocal = new Set(ApiExtractor.mPropertySet);
      systemApiContent.ReservedPropertyNames = Array.from(savedNameAndPropertySet);
      systemApiContent.ReservedLocalNames = Array.from(ApiExtractor.mPropertySet);
    }
    if (systemConfigs.options.enableToplevelObfuscation && systemConfigs.options.enableExportObfuscation) {
      const savedExportNamesSet = new Set(ApiExtractor.mSystemExportSet);
      UnobfuscationCollections.reservedSdkApiForGlobal = savedExportNamesSet;
      systemApiContent.ReservedGlobalNames = Array.from(savedExportNamesSet);
    }

    if (!fs.existsSync(path.dirname(systemApiCachePath))) {
      fs.mkdirSync(path.dirname(systemApiCachePath), { recursive: true });
    }
    fs.writeFileSync(systemApiCachePath, JSON.stringify(systemApiContent, null, 2));
    ApiExtractor.mPropertySet.clear();
    ApiExtractor.mSystemExportSet.clear();
  }

  public getSystemApiCacheForTest(systemConfigs: MergedConfig, systemApiCachePath: string): void {
    return this.getSystemApiCache(systemConfigs, systemApiCachePath);
  }

  private getSdkApiCache(sdkApiPath: string): void {
    ApiExtractor.traverseApiFiles(sdkApiPath, ApiExtractor.ApiType.API);
    const componentPath: string = path.join(sdkApiPath, '../component');
    if (fs.existsSync(componentPath)) {
      ApiExtractor.traverseApiFiles(componentPath, ApiExtractor.ApiType.COMPONENT);
    }
  }

  private getUIApiCache(uiApiPath: string): void {
    ApiExtractor.extractStringsFromFile(uiApiPath);
  }

  private getDependencyConfigs(sourceObConfig: any, dependencyConfigs: MergedConfig): void {
    for (const lib of sourceObConfig.dependencies.libraries || []) {
      if (lib.consumerRules && lib.consumerRules.length > 0) {
        for (const path of lib.consumerRules) {
          const thisLibConfigs = new MergedConfig();
          this.getConfigByPath(path, dependencyConfigs);
          dependencyConfigs.merge(thisLibConfigs);
        }
      }
    }

    if (
      sourceObConfig.dependencies &&
      sourceObConfig.dependencies.hars &&
      sourceObConfig.dependencies.hars.length > 0
    ) {
      for (const path of sourceObConfig.dependencies.hars) {
        const thisHarConfigs = new MergedConfig();
        this.getConfigByPath(path, dependencyConfigs);
        dependencyConfigs.merge(thisHarConfigs);
      }
    }
  }

  public getDependencyConfigsForTest(sourceObConfig: any, dependencyConfigs: MergedConfig): void {
    return this.getDependencyConfigs(sourceObConfig, dependencyConfigs);
  }

  private getSystemApiConfigsByCache(systemApiCachePath: string): void {
    let systemApiContent: {
      ReservedPropertyNames?: string[];
      ReservedGlobalNames?: string[];
      ReservedLocalNames?: string[];
    } = JSON.parse(fs.readFileSync(systemApiCachePath, 'utf-8'));
    if (systemApiContent.ReservedPropertyNames) {
      UnobfuscationCollections.reservedSdkApiForProp = new Set(systemApiContent.ReservedPropertyNames);
    }
    if (systemApiContent.ReservedGlobalNames) {
      UnobfuscationCollections.reservedSdkApiForGlobal = new Set(systemApiContent.ReservedGlobalNames);
    }
    if (systemApiContent.ReservedLocalNames) {
      UnobfuscationCollections.reservedSdkApiForLocal = new Set(systemApiContent.ReservedLocalNames);
    }
  }

  public getSystemApiConfigsByCacheForTest(systemApiCachePath: string): void {
    return this.getSystemApiConfigsByCache(systemApiCachePath);
  }

  private getSelfConsumerConfig(selfConsumerConfig: MergedConfig): void {
    for (const path of this.sourceObConfig.selfConfig.consumerRules) {
      this.getConfigByPath(path, selfConsumerConfig);
    }
  }

  public getSelfConsumerConfigForTest(selfConsumerConfig: MergedConfig): void {
    return this.getSelfConsumerConfig(selfConsumerConfig);
  }

  private getMergedConfigs(selfConfigs: MergedConfig, dependencyConfigs: MergedConfig): MergedConfig {
    if (dependencyConfigs) {
      selfConfigs.merge(dependencyConfigs);
    }
    selfConfigs.sortAndDeduplicate();
    return selfConfigs;
  }

  public getMergedConfigsForTest(selfConfigs: MergedConfig, dependencyConfigs: MergedConfig): MergedConfig {
    return this.getMergedConfigs(selfConfigs, dependencyConfigs);
  }

  private genConsumerConfigFiles(
    sourceObConfig: any,
    selfConsumerConfig: MergedConfig,
    dependencyConfigs: MergedConfig,
  ): void {
    selfConsumerConfig.merge(dependencyConfigs);
    selfConsumerConfig.sortAndDeduplicate();
    this.writeConsumerConfigFile(selfConsumerConfig, sourceObConfig.exportRulePath);
  }

  public genConsumerConfigFilesForTest(
    sourceObConfig: any,
    selfConsumerConfig: MergedConfig,
    dependencyConfigs: MergedConfig,
  ): void {
    return this.genConsumerConfigFiles(sourceObConfig, selfConsumerConfig, dependencyConfigs);
  }

  public writeConsumerConfigFile(selfConsumerConfig: MergedConfig, outpath: string): void {
    const configContent: string = selfConsumerConfig.serializeMergedConfig();
    fs.writeFileSync(outpath, configContent);
  }

  private determineNameCachePath(nameCachePath: string, configPath: string): void {
    if (!fs.existsSync(nameCachePath)) {
      throw new Error(`The applied namecache file '${nameCachePath}' configured by '${configPath}' does not exist.`);
    }
  }
}

/**
 * Collect reserved file name configured in oh-package.json5 and module.json5.
 * @param ohPackagePath The 'main' and 'types' fileds in oh-package.json5 need to be reserved.
 * @param projectConfig Several paths or file contents in projectconfig need to be reserved.
 *   1: module.json's 'srcEntry' field
 *   2: projectPath: /library/src/main/ets
 *   3: cachePath: /library/build/default/cache/default/default@HarCompileArkTs/esmodules/release
 *      target reserved path: /library/build/default/cache/default/default@HarCompileArkTs/esmodules/release/src/main/ets
 *   4: aceModuleBuild/etsFortgz directory: /library/build/default/intermediates/loader_out/etsFortgz
 *      If compile the hsp module, the declaration file will be written to the 'aceModuleBuild/etsFortgz' directory.
 * @param modulePathMap packageName of local har package should be reserved as it is a fixed part of ohmUrl.
 *   example: modulePathMap: { packageName: path }
 * @returns reservedFileNames
 */
export function collectResevedFileNameInIDEConfig(
  ohPackagePath: string,
  projectConfig: any,
  modulePathMap: Object | undefined,
  entryArray: Array<string> | undefined,
): string[] {
  const reservedFileNames: string[] = [];
  const moduleJsonPath: string = projectConfig.aceModuleJsonPath;
  const projectPath: string = projectConfig.projectPath;
  const cachePath: string = projectConfig.cachePath;

  if (entryArray) {
    entryArray.forEach((element) => {
      FileUtils.collectPathReservedString(element, reservedFileNames);
    });
  }

  if (modulePathMap) {
    const modulePaths = Object.values(modulePathMap);
    const moduleNames = Object.keys(modulePathMap);
    modulePaths.forEach((val) => {
      FileUtils.collectPathReservedString(val, reservedFileNames);
    });
    moduleNames.forEach((val) => {
      FileUtils.collectPathReservedString(val, reservedFileNames);
    });
  }
  if (fs.existsSync(ohPackagePath)) {
    const ohPackageContent = JSON5.parse(fs.readFileSync(ohPackagePath, 'utf-8'));
    ohPackageContent.main && FileUtils.collectPathReservedString(ohPackageContent.main, reservedFileNames);
    ohPackageContent.types && FileUtils.collectPathReservedString(ohPackageContent.types, reservedFileNames);
  }

  if (fs.existsSync(moduleJsonPath)) {
    const moduleJsonContent = JSON5.parse(fs.readFileSync(moduleJsonPath, 'utf-8'));
    moduleJsonContent.module?.srcEntry &&
      FileUtils.collectPathReservedString(moduleJsonContent.module?.srcEntry, reservedFileNames);
  }

  if (projectConfig.compileShared || projectConfig.byteCodeHar) {
    FileUtils.collectPathReservedString(projectConfig.aceModuleBuild, reservedFileNames);
    reservedFileNames.push('etsFortgz');
  }

  FileUtils.collectPathReservedString(projectPath, reservedFileNames);
  FileUtils.collectPathReservedString(cachePath, reservedFileNames);
  return reservedFileNames;
}

export function readNameCache(nameCachePath: string, logger: any): void {
  try {
    const fileContent = fs.readFileSync(nameCachePath, 'utf-8');
    const nameCache: {
      compileSdkVersion?: string;
      [key: string]: Object;
      PropertyCache?: Object;
      FileNameCache?: Object;
    } = JSON.parse(fileContent);
    if (nameCache.PropertyCache) {
      PropCollections.historyMangledTable = getMapFromJson(nameCache.PropertyCache);
    }
    if (nameCache.FileNameCache) {
      renameFileNameModule.historyFileNameMangledTable = getMapFromJson(nameCache.FileNameCache);
    }

    const { compileSdkVersion, PropertyCache, FileNameCache, ...rest } = nameCache;
    Object.keys(rest).forEach((key) => {
      nameCacheMap.set(key, rest[key]);
    });
  } catch (err) {
    logger.error(`Failed to open ${nameCachePath}. Error message: ${err}`);
  }
}

/**
 * collect the reserved or excluded paths containing wildcards
 */
export function handleUniversalPathInObf(mergedObConfig: MergedConfig, allSourceFilePaths: Set<string>): void {
  if (
    !mergedObConfig ||
    (mergedObConfig.keepUniversalPaths.length === 0 && mergedObConfig.excludeUniversalPaths.length === 0)
  ) {
    return;
  }
  for (const realFilePath of allSourceFilePaths) {
    let isReserved = false;
    for (const universalPath of mergedObConfig.keepUniversalPaths) {
      if (universalPath.test(realFilePath)) {
        isReserved = true;
        break;
      }
    }
    for (const excludePath of mergedObConfig.excludeUniversalPaths) {
      if (excludePath.test(realFilePath)) {
        isReserved = false;
        mergedObConfig.excludePathSet.add(realFilePath);
        break;
      }
    }
    if (isReserved) {
      mergedObConfig.keepSourceOfPaths.push(realFilePath);
    }
  }
}

export function getArkguardNameCache(
  enablePropertyObfuscation: boolean,
  enableFileNameObfuscation: boolean,
  sdkVersion: string,
  entryPackageInfo: string,
): string {
  let writeContent: string = '';
  let nameCacheCollection: {
    compileSdkVersion?: string;
    PropertyCache?: Object;
    FileNameCache?: Object;
    entryPackageInfo?: string;
  } = Object.fromEntries(nameCacheMap.entries());
  nameCacheCollection.compileSdkVersion = sdkVersion;
  nameCacheCollection.entryPackageInfo = entryPackageInfo;

  if (enablePropertyObfuscation) {
    const mergedPropertyNameCache: Map<string, string> = new Map();
    fillNameCache(PropCollections.historyMangledTable, mergedPropertyNameCache);
    fillNameCache(PropCollections.globalMangledTable, mergedPropertyNameCache);
    nameCacheCollection.PropertyCache = Object.fromEntries(mergedPropertyNameCache);
  }

  if (enableFileNameObfuscation) {
    const mergedFileNameCache: Map<string, string> = new Map();
    fillNameCache(renameFileNameModule.historyFileNameMangledTable, mergedFileNameCache);
    fillNameCache(renameFileNameModule.globalFileNameMangledTable, mergedFileNameCache);
    nameCacheCollection.FileNameCache = Object.fromEntries(mergedFileNameCache);
  }

  writeContent += JSON.stringify(nameCacheCollection, null, 2);
  return writeContent;
}

// export fillNameCache function
export function fillNameCache(table: Map<string, string>, nameCache: Map<string, string>): void {
  if (table) {
    for (const [key, value] of table.entries()) {
      nameCache.set(key, value);
    }
  }
  return;
}

export function writeObfuscationNameCache(
  projectConfig: any,
  entryPackageInfo: string,
  obfuscationCacheDir?: string,
  printNameCache?: string,
): void {
  if (!projectConfig.arkObfuscator) {
    return;
  }
  let options = projectConfig.obfuscationMergedObConfig.options;
  let writeContent = getArkguardNameCache(
    options.enablePropertyObfuscation,
    options.enableFileNameObfuscation,
    projectConfig.etsLoaderVersion,
    entryPackageInfo,
  );
  if (obfuscationCacheDir && obfuscationCacheDir.length > 0) {
    const defaultNameCachePath: string = path.join(obfuscationCacheDir, 'nameCache.json');
    if (!fs.existsSync(path.dirname(defaultNameCachePath))) {
      fs.mkdirSync(path.dirname(defaultNameCachePath), { recursive: true });
    }
    fs.writeFileSync(defaultNameCachePath, writeContent);
  }
  if (printNameCache && printNameCache.length > 0) {
    fs.writeFileSync(printNameCache, writeContent);
  }
}

// Print unobfuscation names, reasons and whitelist, if -print-kept-names is enabled.
export function writeUnobfuscationContent(projectConfig: any): void {
  let obfuscationOptions = projectConfig.obfuscationMergedObConfig.options;
  let unobfuscationOptions = projectConfig.arkObfuscator.mCustomProfiles.mUnobfuscationOption;
  let nameOptions = projectConfig.arkObfuscator.mCustomProfiles.mNameObfuscation;
  if (!unobfuscationOptions.mPrintKeptNames) {
    return;
  }

  let configPath = unobfuscationOptions.mPrintPath;
  let printDir = projectConfig.obfuscationOptions.obfuscationCacheDir;
  let printUnobfPath = path.join(printDir, 'keptNames.json');
  printUnobfuscationReasons(configPath, printUnobfPath);
  let printWhitelistPath = path.join(printDir, 'whitelist.json');
  printWhitelist(obfuscationOptions, nameOptions, printWhitelistPath);
}

// Merge similar whitelists and output according to whether the corresponding options are enabled.
export function printWhitelist(obfuscationOptions: ObOptions, nameOptions: INameObfuscationOption, defaultPath: string): void {
  const enableToplevel = obfuscationOptions.enableToplevelObfuscation;
  const enableProperty = obfuscationOptions.enablePropertyObfuscation;
  const enableStringProp = obfuscationOptions.enableStringPropertyObfuscation;
  const enableExport = obfuscationOptions.enableExportObfuscation;
  const reservedConfToplevelArrary = nameOptions.mReservedToplevelNames ?? [];
  const reservedConfPropertyArray = nameOptions.mReservedProperties ?? [];
  let whitelistObj = {
    lang: [],
    conf: [],
    struct: [],
    exported: [],
    strProp: [],
    enum: []
  };

  let languareSet: Set<string>;
  if (enableProperty) {
    languareSet = mergeSet(UnobfuscationCollections.reservedLangForProperty, LocalVariableCollections.reservedLangForLocal);
  } else {
    languareSet = LocalVariableCollections.reservedLangForLocal;
  }
  whitelistObj.lang = convertSetToArray(languareSet);

  let structSet: Set<string>;
  if (enableProperty) {
    structSet = mergeSet(UnobfuscationCollections.reservedStruct, LocalVariableCollections.reservedStruct);
  } else {
    structSet = LocalVariableCollections.reservedStruct;
  }
  whitelistObj.struct = convertSetToArray(structSet);

  let exportedSet: Set<string>;
  if (enableProperty) {
    exportedSet = UnobfuscationCollections.reservedExportNameAndProp;
  } else if (enableExport) {
    exportedSet = UnobfuscationCollections.reservedExportName;
  }
  whitelistObj.exported = convertSetToArray(exportedSet);

  let stringSet: Set<string>;
  if (enableProperty && !enableStringProp) {
    stringSet = UnobfuscationCollections.reservedStrProp;
  }
  whitelistObj.strProp = convertSetToArray(stringSet);

  whitelistObj.conf = convertSetToArray(LocalVariableCollections.reservedConfig);
  const hasPropertyConfig = enableProperty && reservedConfPropertyArray?.length > 0;
  const hasTopLevelConfig = enableToplevel && reservedConfToplevelArrary?.length > 0;
  if (hasPropertyConfig) {
    whitelistObj.conf.push(...reservedConfPropertyArray);
    handleUniversalReservedList(nameOptions.mUniversalReservedProperties, whitelistObj.conf);
  }
  if (hasTopLevelConfig) {
    whitelistObj.conf.push(...reservedConfToplevelArrary);
    handleUniversalReservedList(nameOptions.mUniversalReservedToplevelNames, whitelistObj.conf);
  }

  let enumSet: Set<string>;
  if (enableProperty) {
    enumSet = UnobfuscationCollections.reservedEnum;
  } 
  whitelistObj.enum = convertSetToArray(enumSet);

  let whitelistContent = JSON.stringify(whitelistObj, null, 2); // 2: indentation
  if (!fs.existsSync(path.dirname(defaultPath))) {
    fs.mkdirSync(path.dirname(defaultPath), { recursive: true });
  }
  fs.writeFileSync(defaultPath, whitelistContent);
}

function handleUniversalReservedList(universalList: RegExp[] | undefined, configArray: string[]): void {
  if (universalList?.length > 0) {
    universalList.forEach((value) => {
      const originalString = UnobfuscationCollections.reservedWildcardMap.get(value);
      if (originalString) {
        configArray.push(originalString);
      }
    });
  }
}

// Merge KeptReasons and KeptNames and output
export function printUnobfuscationReasons(configPath: string, defaultPath: string): void {
  let property: Record<string, string[]> = {};
  let unobfuscationObj = { keptReasons: {}, keptNames: { property } };
  type WhitelistObject = {
    [key in WhitelistType]: string;
  };
  let keptReasons: WhitelistObject = {
    sdk: 'same as the system api names',
    lang: 'same as the language keywords',
    conf: 'same as the user-configured kept name',
    struct: 'same as the ArkUI struct property',
    strProp: 'same as the string property',
    exported: 'same as the exported names and properties',
    enum: 'same as the members in the enum'
  };
  unobfuscationObj.keptReasons = keptReasons;

  if (!historyUnobfuscatedPropMap) {
    // Full build
    UnobfuscationCollections.unobfuscatedPropMap.forEach((value: Set<string>, key: string) => {
      let array: string[] = Array.from(value);
      unobfuscationObj.keptNames.property[key] = array;
    });
  } else {
    // Incremental build
    UnobfuscationCollections.unobfuscatedPropMap.forEach((value: Set<string>, key: string) => {
      let array: string[] = Array.from(value);
      historyUnobfuscatedPropMap.set(key, array);
    });
    historyUnobfuscatedPropMap.forEach((value: string[], key: string) => {
      unobfuscationObj.keptNames.property[key] = value;
    });
  }
  Object.assign(unobfuscationObj.keptNames, unobfuscationNamesObj);
  let unobfuscationContent = JSON.stringify(unobfuscationObj, null, 2);
  if (!fs.existsSync(path.dirname(defaultPath))) {
    fs.mkdirSync(path.dirname(defaultPath), { recursive: true });
  }
  fs.writeFileSync(defaultPath, unobfuscationContent);
  
  if (!fs.existsSync(path.dirname(configPath))) {
    fs.mkdirSync(path.dirname(configPath), { recursive: true });
  }
  if (configPath) {
    fs.copyFileSync(defaultPath, configPath);
  }
}


export function generateConsumerObConfigFile(obfuscationOptions: any, logger: any): void {
  const projectConfig = { obfuscationOptions, compileHar: true };
  const obConfig: ObConfigResolver = new ObConfigResolver(projectConfig, logger);
  obConfig.resolveObfuscationConfigs();
}

export function mangleFilePath(originalPath: string): string {
  const mangledFilePath = renameFileNameModule.getMangleCompletePath(originalPath);
  return mangledFilePath;
}

export function enableObfuscatedFilePathConfig(isPackageModules: boolean, projectConfig: any): boolean {
  const isDebugMode = isDebug(projectConfig);
  const hasObfuscationConfig = projectConfig.obfuscationMergedObConfig;
  if (isDebugMode || !hasObfuscationConfig) {
    return false;
  }
  const disableObfuscation = hasObfuscationConfig.options.disableObfuscation;
  const enableFileNameObfuscation = hasObfuscationConfig.options.enableFileNameObfuscation;
  if (disableObfuscation || !enableFileNameObfuscation) {
    return false;
  }
  return true;
}

export function handleObfuscatedFilePath(filePath: string, isPackageModules: boolean, projectConfig: Object): string {
  if (!enableObfuscatedFilePathConfig(isPackageModules, projectConfig)) {
    return filePath;
  }
  // Do not obfuscate the file path in dir oh_modules.
  if (!isPackageModules) {
    return mangleFilePath(filePath);
  }
  // When open the config 'enableFileNameObfuscation', keeping all paths in unix format.
  return FileUtils.toUnixPath(filePath);
}

export function enableObfuscateFileName(isPackageModules: boolean, projectConfig: Object): boolean {
  if (!enableObfuscatedFilePathConfig(isPackageModules, projectConfig)) {
    return false;
  }

  // Do not obfuscate the file path in dir oh_modules.
  if (!isPackageModules) {
    return true;
  }
  // When open the config 'enableFileNameObfuscation', keeping all paths in unix format.
  return false;
}

/**
 * Get the relative path relative to the project based on the file's associated project
 */
export function getRelativeSourcePath(
  filePath: string,
  projectRootPath: string,
  belongProjectPath: string | undefined,
): string {
  filePath = FileUtils.toUnixPath(filePath);

  if (projectRootPath) {
    projectRootPath = FileUtils.toUnixPath(projectRootPath);
  }

  if (belongProjectPath) {
    belongProjectPath = FileUtils.toUnixPath(belongProjectPath);
  }

  let relativeFilePath: string = filePath;
  if (projectRootPath && filePath.startsWith(projectRootPath)) {
    relativeFilePath = filePath.replace(projectRootPath + '/', '');
  } else if (belongProjectPath) {
    relativeFilePath = filePath.replace(belongProjectPath + '/', '');
  }

  return relativeFilePath;
}
