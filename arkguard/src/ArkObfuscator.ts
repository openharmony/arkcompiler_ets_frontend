/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

import {
  createPrinter,
  createTextWriter,
  transform,
  createObfTextSingleLineWriter,
} from 'typescript';

import type {
  CompilerOptions,
  EmitTextWriter,
  Node,
  Printer,
  PrinterOptions,
  RawSourceMap,
  SourceFile,
  SourceMapGenerator,
  TransformationResult,
  TransformerFactory,
} from 'typescript';

import * as fs from 'fs';
import path from 'path';
import sourceMap from 'source-map';

import type { IOptions } from './configs/IOptions';
import { FileUtils } from './utils/FileUtils';
import { TransformerManager } from './transformers/TransformerManager';
import { getSourceMapGenerator } from './utils/SourceMapUtil';
import {
  decodeSourcemap,
  ExistingDecodedSourceMap,
  Source,
  SourceMapLink,
  SourceMapSegmentObj,
  mergeSourceMap
} from './utils/SourceMapMergingUtil';
import {
  deleteLineInfoForNameString,
  getMapFromJson,
  NAME_CACHE_SUFFIX,
  PROPERTY_CACHE_FILE,
  IDENTIFIER_CACHE,
  MEM_METHOD_CACHE,
  readCache,
  writeCache,
} from './utils/NameCacheUtil';
import { ListUtil } from './utils/ListUtil';
import { needReadApiInfo, readProjectProperties, readProjectPropertiesByCollectedPaths } from './common/ApiReader';
import { ApiExtractor } from './common/ApiExtractor';
import esInfo from './configs/preset/es_reserved_properties.json';
import { EventList, TimeSumPrinter, TimeTracker } from './utils/PrinterUtils';
import { Extension, type ProjectInfo } from './common/type';
export { FileUtils } from './utils/FileUtils';
export { MemoryUtils } from './utils/MemoryUtils';
import { TypeUtils } from './utils/TypeUtils';
import { handleReservedConfig } from './utils/TransformUtil';
export { separateUniversalReservedItem, containWildcards, wildcardTransformer } from './utils/TransformUtil';
export type { ReservedNameInfo } from './utils/TransformUtil';

export const renameIdentifierModule = require('./transformers/rename/RenameIdentifierTransformer');
export const renamePropertyModule = require('./transformers/rename/RenamePropertiesTransformer');
export const renameFileNameModule = require('./transformers/rename/RenameFileNameTransformer');

export { getMapFromJson, readProjectPropertiesByCollectedPaths, deleteLineInfoForNameString };
export let orignalFilePathForSearching: string | undefined;
export interface PerformancePrinter {
  filesPrinter?: TimeTracker;
  singleFilePrinter?: TimeTracker;
  timeSumPrinter?: TimeSumPrinter;
  iniPrinter: TimeTracker;
}
export let performancePrinter: PerformancePrinter = {
  iniPrinter: new TimeTracker(),
};

type ObfuscationResultType = {
  content: string;
  sourceMap?: RawSourceMap;
  nameCache?: { [k: string]: string | {} };
  filePath?: string;
};

const JSON_TEXT_INDENT_LENGTH: number = 2;
export class ArkObfuscator {
  // Used only for testing
  private mWriteOriginalFile: boolean = false;

  // A text writer of Printer
  private mTextWriter: EmitTextWriter;

  // A list of source file path
  private readonly mSourceFiles: string[];

  // Path of obfuscation configuration file.
  private readonly mConfigPath: string;

  // Compiler Options for typescript,use to parse ast
  private readonly mCompilerOptions: CompilerOptions;

  // User custom obfuscation profiles.
  private mCustomProfiles: IOptions;

  private mTransformers: TransformerFactory<Node>[];

  static mProjectInfo: ProjectInfo | undefined;

  // If isKeptCurrentFile is true, both identifier and property obfuscation are skipped.
  static mIsKeptCurrentFile: boolean = false;

  public constructor(sourceFiles?: string[], configPath?: string) {
    this.mSourceFiles = sourceFiles;
    this.mConfigPath = configPath;
    this.mCompilerOptions = {};
    this.mTransformers = [];
  }

  public setWriteOriginalFile(flag: boolean): void {
    this.mWriteOriginalFile = flag;
  }

  public addReservedProperties(newReservedProperties: string[]): void {
    if (newReservedProperties.length === 0) {
      return;
    }
    const nameObfuscationConfig = this.mCustomProfiles.mNameObfuscation;
    nameObfuscationConfig.mReservedProperties = ListUtil.uniqueMergeList(newReservedProperties,
      nameObfuscationConfig?.mReservedProperties);
  }

  public addReservedNames(newReservedNames: string[]): void {
    if (newReservedNames.length === 0) {
      return;
    }
    const nameObfuscationConfig = this.mCustomProfiles.mNameObfuscation;
    nameObfuscationConfig.mReservedNames = ListUtil.uniqueMergeList(newReservedNames,
      nameObfuscationConfig?.mReservedNames);
  }

  public setKeepSourceOfPaths(mKeepSourceOfPaths: Set<string>): void {
    this.mCustomProfiles.mKeepFileSourceCode.mKeepSourceOfPaths = mKeepSourceOfPaths;
  }

  public handleTsHarComments(sourceFile: SourceFile, originalPath: string | undefined): void {
    if (ArkObfuscator.projectInfo?.useTsHar && (originalPath?.endsWith(Extension.ETS) && !originalPath?.endsWith(Extension.DETS))) {
      // @ts-ignore
      sourceFile.writeTsHarComments = true;
    }
  }

  public get customProfiles(): IOptions {
    return this.mCustomProfiles;
  }

  public get configPath(): string {
    return this.mConfigPath;
  }

  public static get isKeptCurrentFile(): boolean {
    return ArkObfuscator.mIsKeptCurrentFile;
  }

  public static set isKeptCurrentFile(isKeptFile: boolean) {
    ArkObfuscator.mIsKeptCurrentFile = isKeptFile;
  }

  public static get projectInfo(): ProjectInfo {
    return ArkObfuscator.mProjectInfo;
  }

  public static set projectInfo(projectInfo: ProjectInfo) {
    ArkObfuscator.mProjectInfo = projectInfo;
  }

  private isCurrentFileInKeepPaths(customProfiles: IOptions, originalFilePath: string): boolean {
    const keepFileSourceCode = customProfiles.mKeepFileSourceCode;
    if (keepFileSourceCode === undefined || keepFileSourceCode.mKeepSourceOfPaths.size === 0) {
      return false;
    }
    const keepPaths: Set<string> = keepFileSourceCode.mKeepSourceOfPaths;
    const originalPath = FileUtils.toUnixPath(originalFilePath);
    return keepPaths.has(originalPath);
  }

  /**
   * init ArkObfuscator according to user config
   * should be called after constructor
   */
  public init(config?: IOptions): boolean {
    if (!this.mConfigPath && !config) {
      console.error('obfuscation config file is not found and no given config.');
      return false;
    }

    if (this.mConfigPath) {
      config = FileUtils.readFileAsJson(this.mConfigPath);
      // this.mConfigPath from Arkguard unit test
      handleReservedConfig(config, 'mNameObfuscation', 'mReservedProperties', 'mUniversalReservedProperties');
      handleReservedConfig(config, 'mNameObfuscation', 'mReservedToplevelNames', 'mUniversalReservedToplevelNames');
    }

    handleReservedConfig(config, 'mRenameFileName', 'mReservedFileNames', 'mUniversalReservedFileNames');
    handleReservedConfig(config, 'mRemoveDeclarationComments', 'mReservedComments', 'mUniversalReservedComments', 'mEnable');
    this.mCustomProfiles = config;

    if (this.mCustomProfiles.mCompact) {
      this.mTextWriter = createObfTextSingleLineWriter();
    } else {
      this.mTextWriter = createTextWriter('\n');
    }

    if (this.mCustomProfiles.mEnableSourceMap) {
      this.mCompilerOptions.sourceMap = true;
    }

    this.initPerformancePrinter();
    // load transformers
    this.mTransformers = new TransformerManager(this.mCustomProfiles).getTransformers();

    if (needReadApiInfo(this.mCustomProfiles)) {
      this.mCustomProfiles.mNameObfuscation.mReservedProperties = ListUtil.uniqueMergeList(
        this.mCustomProfiles.mNameObfuscation.mReservedProperties,
        this.mCustomProfiles.mNameObfuscation.mReservedNames,
        [...esInfo.es2015, ...esInfo.es2016, ...esInfo.es2017, ...esInfo.es2018, ...esInfo.es2019, ...esInfo.es2020,
          ...esInfo.es2021]);
    }

    return true;
  }

  /**
   * Obfuscate all the source files.
   */
  public async obfuscateFiles(): Promise<void> {
    if (!path.isAbsolute(this.mCustomProfiles.mOutputDir)) {
      this.mCustomProfiles.mOutputDir = path.join(path.dirname(this.mConfigPath), this.mCustomProfiles.mOutputDir);
    }
    if (this.mCustomProfiles.mOutputDir && !fs.existsSync(this.mCustomProfiles.mOutputDir)) {
      fs.mkdirSync(this.mCustomProfiles.mOutputDir);
    }

    performancePrinter?.filesPrinter?.startEvent(EventList.ALL_FILES_OBFUSCATION);
    readProjectProperties(this.mSourceFiles, this.mCustomProfiles);
    const propertyCachePath = path.join(this.mCustomProfiles.mOutputDir, 
                                        path.basename(this.mSourceFiles[0])); // Get dir name
    this.readPropertyCache(propertyCachePath);

    // support directory and file obfuscate
    for (const sourcePath of this.mSourceFiles) {
      if (!fs.existsSync(sourcePath)) {
        console.error(`File ${FileUtils.getFileName(sourcePath)} is not found.`);
        return;
      }

      if (fs.lstatSync(sourcePath).isFile()) {
        await this.obfuscateFile(sourcePath, this.mCustomProfiles.mOutputDir);
        continue;
      }

      const dirPrefix: string = FileUtils.getPrefix(sourcePath);
      await this.obfuscateDir(sourcePath, dirPrefix);
    }

    this.producePropertyCache(propertyCachePath);
    performancePrinter?.filesPrinter?.endEvent(EventList.ALL_FILES_OBFUSCATION);
    performancePrinter?.timeSumPrinter?.print('Sum up time of processes');
    performancePrinter?.timeSumPrinter?.summarizeEventDuration();
  }

  /**
   * obfuscate directory
   * @private
   */
  private async obfuscateDir(dirName: string, dirPrefix: string): Promise<void> {
    const currentDir: string = FileUtils.getPathWithoutPrefix(dirName, dirPrefix);
    let newDir: string = this.mCustomProfiles.mOutputDir;
    // there is no need to create directory because the directory names will be obfuscated.
    if (!this.mCustomProfiles.mRenameFileName?.mEnable) {
      newDir = path.join(this.mCustomProfiles.mOutputDir, currentDir);
      if (!fs.existsSync(newDir)) {
        fs.mkdirSync(newDir);
      }
    }

    const fileNames: string[] = fs.readdirSync(dirName);
    for (let fileName of fileNames) {
      const filePath: string = path.join(dirName, fileName);
      if (fs.lstatSync(filePath).isFile()) {
        await this.obfuscateFile(filePath, newDir);
        continue;
      }

      await this.obfuscateDir(filePath, dirPrefix);
    }
  }

  private readNameCache(sourceFile: string, outputDir: string): void {
    if (!this.mCustomProfiles.mNameObfuscation?.mEnable || !this.mCustomProfiles.mEnableNameCache) {
      return;
    }

    const nameCachePath: string = path.join(outputDir, FileUtils.getFileName(sourceFile) + NAME_CACHE_SUFFIX);
    const nameCache: Object = readCache(nameCachePath);
    let historyNameCache = new Map<string, string>();
    let identifierCache = nameCache ? Reflect.get(nameCache, IDENTIFIER_CACHE) : undefined;
    deleteLineInfoForNameString(historyNameCache, identifierCache);

    renameIdentifierModule.historyNameCache = historyNameCache;
  }

  private readPropertyCache(outputDir: string): void {
    if (!this.mCustomProfiles.mNameObfuscation?.mRenameProperties || !this.mCustomProfiles.mEnableNameCache) {
      return;
    }

    const propertyCachePath: string = path.join(outputDir, PROPERTY_CACHE_FILE);
    const propertyCache: Object = readCache(propertyCachePath);
    if (!propertyCache) {
      return;
    }

    renamePropertyModule.historyMangledTable = getMapFromJson(propertyCache);
  }

  private produceNameCache(namecache: { [k: string]: string | {} }, resultPath: string): void {
    const nameCachePath: string = resultPath + NAME_CACHE_SUFFIX;
    fs.writeFileSync(nameCachePath, JSON.stringify(namecache, null, JSON_TEXT_INDENT_LENGTH));
  }

  private producePropertyCache(outputDir: string): void {
    if (this.mCustomProfiles.mNameObfuscation &&
      this.mCustomProfiles.mNameObfuscation.mRenameProperties &&
      this.mCustomProfiles.mEnableNameCache) {
      const propertyCachePath: string = path.join(outputDir, PROPERTY_CACHE_FILE);
      writeCache(renamePropertyModule.globalMangledTable, propertyCachePath);
    }
  }

  private initPerformancePrinter(): void {
    if (this.mCustomProfiles.mPerformancePrinter) {
      const printConfig = this.mCustomProfiles.mPerformancePrinter;
      const printPath = printConfig.mOutputPath;

      if (printConfig.mFilesPrinter) {
        performancePrinter.filesPrinter = performancePrinter.iniPrinter;
        performancePrinter.filesPrinter.setOutputPath(printPath);
      } else {
        performancePrinter.iniPrinter = undefined;
      }

      if (printConfig.mSingleFilePrinter) {
        performancePrinter.singleFilePrinter = new TimeTracker(printPath);
      }

      if (printConfig.mSumPrinter) {
        performancePrinter.timeSumPrinter = new TimeSumPrinter(printPath);
      }
    } else {
      performancePrinter = undefined;
    }
  }

  /**
   * A Printer to output obfuscated codes.
   */
  public createObfsPrinter(isDeclarationFile: boolean): Printer {
    // set print options
    let printerOptions: PrinterOptions = {};
    let removeOption = this.mCustomProfiles.mRemoveDeclarationComments;
    let hasReservedList = removeOption?.mReservedComments?.length || removeOption?.mUniversalReservedComments?.length;
    let keepDeclarationComments = hasReservedList || !removeOption?.mEnable;

    if (isDeclarationFile && keepDeclarationComments) {
      printerOptions.removeComments = false;
    }
    if ((!isDeclarationFile && this.mCustomProfiles.mRemoveComments) || (isDeclarationFile && !keepDeclarationComments)) {
      printerOptions.removeComments = true;
    }

    return createPrinter(printerOptions);
  }

  private isObfsIgnoreFile(fileName: string): boolean {
    let suffix: string = FileUtils.getFileExtension(fileName);

    return suffix !== 'js' && suffix !== 'ts' && suffix !== 'ets';
  }

  private convertLineBasedOnSourceMap(targetCache: string, sourceMapLink?: SourceMapLink): Map<string, string> {
    let originalCache: Map<string, string> = renameIdentifierModule.nameCache.get(targetCache);
    let updatedCache: Map<string, string> = new Map<string, string>();
    for (const [key, value] of originalCache) {
      if (!key.includes(':')) {
        // No need to save line info for identifier which is not function-like, i.e. key without ':' here.
        updatedCache[key] = value;
        continue;
      }
      const [scopeName, oldStartLine, oldStartColumn, oldEndLine, oldEndColumn] = key.split(':');
      let newKey: string = key;
      if (!sourceMapLink) {
        // In Arkguard, we save line info of source code, so do not need to use sourcemap mapping.
        newKey = `${scopeName}:${oldStartLine}:${oldEndLine}`;
        updatedCache[newKey] = value;
        continue;
      }
      const startPosition: SourceMapSegmentObj | null = sourceMapLink.traceSegment(
        // 1: The line number in originalCache starts from 1 while in source map starts from 0.
        Number(oldStartLine) - 1, Number(oldStartColumn) - 1, ''); // Minus 1 to get the correct original position.
      if (!startPosition) {
        // Do not save methods that do not exist in the source code, e.g. 'build' in ArkUI.
        continue;
      }
      const endPosition: SourceMapSegmentObj | null = sourceMapLink.traceSegment(
        Number(oldEndLine) - 1, Number(oldEndColumn) - 1, ''); // 1: Same as above.
      if (!endPosition) {
        // Do not save methods that do not exist in the source code, e.g. 'build' in ArkUI.
        continue;
      }
      const startLine = startPosition.line + 1; // 1: The final line number in updatedCache should starts from 1.
      const endLine = endPosition.line + 1; // 1: Same as above.
      newKey = `${scopeName}:${startLine}:${endLine}`;
      updatedCache[newKey] = value;
    }
    return updatedCache;
  }

  /**
   * Obfuscate single source file with path provided
   *
   * @param sourceFilePath single source file path
   * @param outputDir
   */
  public async obfuscateFile(sourceFilePath: string, outputDir: string): Promise<void> {
    const fileName: string = FileUtils.getFileName(sourceFilePath);
    if (this.isObfsIgnoreFile(fileName)) {
      fs.copyFileSync(sourceFilePath, path.join(outputDir, fileName));
      return;
    }

    // Add the whitelist of file name obfuscation for ut.
    if (this.mCustomProfiles.mRenameFileName?.mEnable) {
      const reservedArray = this.mCustomProfiles.mRenameFileName.mReservedFileNames;
      FileUtils.collectPathReservedString(this.mConfigPath, reservedArray);
    }
    let content: string = FileUtils.readFile(sourceFilePath);
    this.readNameCache(sourceFilePath, outputDir);
    performancePrinter?.filesPrinter?.startEvent(sourceFilePath);
    const mixedInfo: ObfuscationResultType = await this.obfuscate(content, sourceFilePath);
    performancePrinter?.filesPrinter?.endEvent(sourceFilePath, undefined, true);

    if (this.mWriteOriginalFile && mixedInfo) {
      // Write the obfuscated content directly to orignal file.
      fs.writeFileSync(sourceFilePath, mixedInfo.content);
      return;
    }
    if (outputDir && mixedInfo) {
      // the writing file is for the ut.
      const testCasesRootPath = path.join(__dirname, '../', 'test/grammar');
      let relativePath = '';
      let resultPath = '';
      if (this.mCustomProfiles.mRenameFileName?.mEnable && mixedInfo.filePath) {
        relativePath = mixedInfo.filePath.replace(testCasesRootPath, '');
      } else {
        relativePath = sourceFilePath.replace(testCasesRootPath, '');
      }
      resultPath = path.join(this.mCustomProfiles.mOutputDir, relativePath);
      fs.mkdirSync(path.dirname(resultPath), { recursive: true });
      fs.writeFileSync(resultPath, mixedInfo.content);

      if (this.mCustomProfiles.mEnableSourceMap && mixedInfo.sourceMap) {
        fs.writeFileSync(path.join(resultPath + '.map'),
          JSON.stringify(mixedInfo.sourceMap, null, JSON_TEXT_INDENT_LENGTH));
      }

      if (this.mCustomProfiles.mEnableNameCache && this.mCustomProfiles.mEnableNameCache) {
        this.produceNameCache(mixedInfo.nameCache, resultPath);
      }
    }
  }

  /**
   * Obfuscate ast of a file.
   * @param content ast or source code of a source file
   * @param sourceFilePath
   * @param previousStageSourceMap
   * @param historyNameCache
   * @param originalFilePath When filename obfuscation is enabled, it is used as the source code path.
   */
  public async obfuscate(
    content: SourceFile | string,
    sourceFilePath: string,
    previousStageSourceMap?: RawSourceMap,
    historyNameCache?: Map<string, string>,
    originalFilePath?: string,
    projectInfo?: ProjectInfo,
  ): Promise<ObfuscationResultType> {
    ArkObfuscator.projectInfo = projectInfo;
    let ast: SourceFile;
    let result: ObfuscationResultType = { content: undefined };
    if (this.isObfsIgnoreFile(sourceFilePath)) {
      // need add return value
      return result;
    }

    performancePrinter?.singleFilePrinter?.startEvent(EventList.CREATE_AST, performancePrinter.timeSumPrinter, sourceFilePath);
    if (typeof content === 'string') {
      ast = TypeUtils.createObfSourceFile(sourceFilePath, content);
    } else {
      ast = content;
    }
    performancePrinter?.singleFilePrinter?.endEvent(EventList.CREATE_AST, performancePrinter.timeSumPrinter);

    if (ast.statements.length === 0) {
      return result;
    }

    if (historyNameCache && historyNameCache.size > 0 && this.mCustomProfiles.mNameObfuscation) {
      renameIdentifierModule.historyNameCache = historyNameCache;
    }
    originalFilePath = originalFilePath ?? ast.fileName;
    if (this.mCustomProfiles.mRenameFileName?.mEnable) {
      orignalFilePathForSearching = originalFilePath;
    }
    ArkObfuscator.isKeptCurrentFile = this.isCurrentFileInKeepPaths(this.mCustomProfiles, originalFilePath);

    if (ast.isDeclarationFile) {
      if (!this.mCustomProfiles.mRemoveDeclarationComments || !this.mCustomProfiles.mRemoveDeclarationComments.mEnable) {
        //@ts-ignore
        ast.reservedComments = undefined;
        //@ts-ignore
        ast.universalReservedComments = undefined;
      } else {
        //@ts-ignore
        ast.reservedComments ??= this.mCustomProfiles.mRemoveDeclarationComments.mReservedComments ?
          this.mCustomProfiles.mRemoveDeclarationComments.mReservedComments : [];
        //@ts-ignore
        ast.universalReservedComments = this.mCustomProfiles.mRemoveDeclarationComments.mUniversalReservedComments ?? [];
      }
    } else {
      //@ts-ignore
      ast.reservedComments = this.mCustomProfiles.mRemoveComments ? [] : undefined;
      //@ts-ignore
      ast.universalReservedComments = this.mCustomProfiles.mRemoveComments ? [] : undefined;
    }

    performancePrinter?.singleFilePrinter?.startEvent(EventList.OBFUSCATE_AST, performancePrinter.timeSumPrinter);
    let transformedResult: TransformationResult<Node> = transform(ast, this.mTransformers, this.mCompilerOptions);
    performancePrinter?.singleFilePrinter?.endEvent(EventList.OBFUSCATE_AST, performancePrinter.timeSumPrinter);
    ast = transformedResult.transformed[0] as SourceFile;

    // convert ast to output source file and generate sourcemap if needed.
    let sourceMapGenerator: SourceMapGenerator = undefined;
    if (this.mCustomProfiles.mEnableSourceMap) {
      sourceMapGenerator = getSourceMapGenerator(sourceFilePath);
    }

    if (sourceFilePath.endsWith('.js')) {
      TypeUtils.tsToJs(ast);
    }
    this.handleTsHarComments(ast, originalFilePath);
    performancePrinter?.singleFilePrinter?.startEvent(EventList.CREATE_PRINTER, performancePrinter.timeSumPrinter);
    this.createObfsPrinter(ast.isDeclarationFile).writeFile(ast, this.mTextWriter, sourceMapGenerator);
    performancePrinter?.singleFilePrinter?.endEvent(EventList.CREATE_PRINTER, performancePrinter.timeSumPrinter);

    result.filePath = ast.fileName;
    result.content = this.mTextWriter.getText();

    if (this.mCustomProfiles.mEnableSourceMap && sourceMapGenerator) {
      let sourceMapJson: RawSourceMap = sourceMapGenerator.toJSON();
      sourceMapJson.sourceRoot = '';
      sourceMapJson.file = path.basename(sourceFilePath);
      if (previousStageSourceMap) {
        sourceMapJson = mergeSourceMap(previousStageSourceMap as RawSourceMap, sourceMapJson);
      }
      result.sourceMap = sourceMapJson;
      let nameCache = renameIdentifierModule.nameCache;
      if (this.mCustomProfiles.mEnableNameCache) {
        let newIdentifierCache!: Object;
        let newMemberMethodCache!: Object;
        if (previousStageSourceMap) {
          // The process in sdk, need to use sourcemap mapping.
          // 1: Only one file in the source map; 0: The first and the only one.
          const sourceFileName = previousStageSourceMap.sources?.length === 1 ? previousStageSourceMap.sources[0] : '';
          const source: Source = new Source(sourceFileName, null);
          const decodedSourceMap: ExistingDecodedSourceMap = decodeSourcemap(previousStageSourceMap);
          let sourceMapLink: SourceMapLink = new SourceMapLink(decodedSourceMap, [source]);
          newIdentifierCache = this.convertLineBasedOnSourceMap(IDENTIFIER_CACHE, sourceMapLink);
          newMemberMethodCache = this.convertLineBasedOnSourceMap(MEM_METHOD_CACHE, sourceMapLink);
        } else {
          // The process in Arkguard.
          newIdentifierCache = this.convertLineBasedOnSourceMap(IDENTIFIER_CACHE);
          newMemberMethodCache = this.convertLineBasedOnSourceMap(MEM_METHOD_CACHE);
        }
        nameCache.set(IDENTIFIER_CACHE, newIdentifierCache);
        nameCache.set(MEM_METHOD_CACHE, newMemberMethodCache);
        result.nameCache = { [IDENTIFIER_CACHE]: newIdentifierCache, [MEM_METHOD_CACHE]: newMemberMethodCache };
      }
    }

    // clear cache of text writer
    this.mTextWriter.clear();
    if (renameIdentifierModule.nameCache) {
      renameIdentifierModule.nameCache.clear();
      renameIdentifierModule.identifierLineMap.clear();
      renameIdentifierModule.classMangledName.clear();
    }

    renameIdentifierModule.historyNameCache = undefined;
    return result;
  }
}

export { ApiExtractor };
