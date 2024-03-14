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
  createSourceFile, createTextWriter,
  ScriptTarget,
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

import type {IOptions} from './configs/IOptions';
import {FileUtils} from './utils/FileUtils';
import {TransformerManager} from './transformers/TransformerManager';
import {getSourceMapGenerator} from './utils/SourceMapUtil';

import {
  deleteLineInfoForNameString,
  getMapFromJson,
  NAME_CACHE_SUFFIX,
  PROPERTY_CACHE_FILE,
  IDENTIFIER_CACHE,
  MEM_METHOD_CACHE,
  readCache, writeCache
} from './utils/NameCacheUtil';
import {ListUtil} from './utils/ListUtil';
import {needReadApiInfo, readProjectProperties, readProjectPropertiesByCollectedPaths} from './common/ApiReader';
import {ApiExtractor} from './common/ApiExtractor';
import esInfo from './configs/preset/es_reserved_properties.json';
import {EventList, TimeSumPrinter, TimeTracker} from './utils/PrinterUtils';
export {FileUtils} from './utils/FileUtils';

export const renameIdentifierModule = require('./transformers/rename/RenameIdentifierTransformer');
export const renamePropertyModule = require('./transformers/rename/RenamePropertiesTransformer');
export const renameFileNameModule = require('./transformers/rename/RenameFileNameTransformer');

export {getMapFromJson, readProjectPropertiesByCollectedPaths, deleteLineInfoForNameString};
export let orignalFilePathForSearching: string | undefined;
export interface PerformancePrinter {
  filesPrinter?: TimeTracker;
  singleFilePrinter?: TimeTracker;
  timeSumPrinter?: TimeSumPrinter;
  iniPrinter: TimeTracker;
}
export let performancePrinter: PerformancePrinter = {
  iniPrinter: new TimeTracker()
};

type ObfuscationResultType = {
  content: string,
  sourceMap?: RawSourceMap,
  nameCache?: { [k: string] : string | {} },
  filePath?: string
};

const JSON_TEXT_INDENT_LENGTH: number = 2;
export class ArkObfuscator {
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
  
  // If isKeptCurrentFile is true, both identifier and property obfuscation are skipped.
  static mIsKeptCurrentFile: boolean = false;

  public constructor(sourceFiles?: string[], configPath?: string) {
    this.mSourceFiles = sourceFiles;
    this.mConfigPath = configPath;
    this.mCompilerOptions = {};
    this.mTransformers = [];
  }

  public addReservedProperties(newReservedProperties: string[]) {
    if (newReservedProperties.length === 0) {
      return;
    }
    const nameObfuscationConfig = this.mCustomProfiles.mNameObfuscation;
    nameObfuscationConfig.mReservedProperties = ListUtil.uniqueMergeList(newReservedProperties,
      nameObfuscationConfig?.mReservedProperties);
  }

  public addReservedNames(newReservedNames: string[]) {
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

  public get customProfiles(): IOptions {
    return this.mCustomProfiles;
  }

  public get configPath(): string {
    return this.mConfigPath;
  }

  public static get isKeptCurrentFile() {
    return ArkObfuscator.mIsKeptCurrentFile;
  }

  public static set isKeptCurrentFile(isKeptFile: boolean) {
    ArkObfuscator.mIsKeptCurrentFile = isKeptFile;
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
    }

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
    this.mTransformers = TransformerManager.getInstance(this.mCustomProfiles).getTransformers();

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
    this.readPropertyCache(this.mCustomProfiles.mOutputDir);

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

    this.producePropertyCache(this.mCustomProfiles.mOutputDir);
    performancePrinter?.filesPrinter?.endEvent(EventList.ALL_FILES_OBFUSCATION);
    performancePrinter?.timeSumPrinter?.print('Sum up time of processes')
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

  private produceNameCache(namecache: { [k: string]: string | {}}, resultPath: string): void {
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

  async mergeSourceMap(originMap: sourceMap.RawSourceMap, newMap: sourceMap.RawSourceMap): Promise<RawSourceMap> {
    if (!originMap) {
      return newMap as RawSourceMap;
    }

    if (!newMap) {
      return originMap as RawSourceMap;
    }

    const originConsumer: sourceMap.SourceMapConsumer = await new sourceMap.SourceMapConsumer(originMap);
    const newConsumer: sourceMap.SourceMapConsumer = await new sourceMap.SourceMapConsumer(newMap);
    const newMappingList: sourceMap.MappingItem[] = [];
    newConsumer.eachMapping((mapping: sourceMap.MappingItem) => {
      if (mapping.originalLine == null) {
        return;
      }

      const originalPos = originConsumer.originalPositionFor({
        line: mapping.originalLine,
        column: mapping.originalColumn
      });

      if (originalPos.source == null) {
        return;
      }

      mapping.originalLine = originalPos.line;
      mapping.originalColumn = originalPos.column;
      newMappingList.push(mapping);
    });

    const updatedGenerator: sourceMap.SourceMapGenerator = sourceMap.SourceMapGenerator.fromSourceMap(newConsumer);
    updatedGenerator['_file'] = originMap.file;
    updatedGenerator['_mappings']['_array'] = newMappingList;
    return JSON.parse(updatedGenerator.toString()) as RawSourceMap;
  }

  /**
   * A Printer to output obfuscated codes.
   */
  public createObfsPrinter(isDeclarationFile: boolean): Printer {
    // set print options
    let printerOptions: PrinterOptions = {};
    let removeOption = this.mCustomProfiles.mRemoveDeclarationComments;
    let keepDeclarationComments = !removeOption || !removeOption.mEnable || (removeOption.mReservedComments && removeOption.mReservedComments.length > 0);
    
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

    return (suffix !== 'js' && suffix !== 'ts' && suffix !== 'ets');
  }

  private convertLineInfoForCache(consumer: sourceMap.SourceMapConsumer, targetCache: string) : Object {
    let originalCache : Map<string, string> = renameIdentifierModule.nameCache.get(targetCache);
    let updatedCache: Object = {};
    for (const [key, value] of originalCache) {
      let newKey: string = key;
      if (!key.includes(':')) {
        updatedCache[newKey] = value;
        continue;
      }
      const [scopeName, oldStartLine, oldStartColum, oldEndLine, oldEndColum] = key.split(':');
      const startPosition = consumer.originalPositionFor({line: Number(oldStartLine), column: Number(oldStartColum)});
      const startLine = startPosition.line;
      const endPosition = consumer.originalPositionFor({line: Number(oldEndLine), column: Number(oldEndColum)});
      const endLine = endPosition.line;
      newKey = `${scopeName}:${startLine}:${endLine}`;
      // Do not save methods that do not exist in the source code, e.g. 'build' in ArkUI.
      if (startLine && endLine) {
        updatedCache[newKey] = value;
      }
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
      this.mCustomProfiles.mRenameFileName.mReservedFileNames.push(this.mConfigPath);
    }
    let content: string = FileUtils.readFile(sourceFilePath);
    this.readNameCache(sourceFilePath, outputDir);
    performancePrinter?.filesPrinter?.startEvent(sourceFilePath);
    const mixedInfo: ObfuscationResultType = await this.obfuscate(content, sourceFilePath);
    performancePrinter?.filesPrinter?.endEvent(sourceFilePath, undefined, true);

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
      fs.mkdirSync(path.dirname(resultPath), {recursive: true});
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
  public async obfuscate(content: SourceFile | string, sourceFilePath: string, previousStageSourceMap?: sourceMap.RawSourceMap, 
    historyNameCache?: Map<string, string>, originalFilePath?: string): Promise<ObfuscationResultType> {
    let ast: SourceFile;
    let result: ObfuscationResultType = { content: undefined };
    if (this.isObfsIgnoreFile(sourceFilePath)) {
      // need add return value
      return result;
    }

    performancePrinter?.singleFilePrinter?.startEvent(EventList.CREATE_AST, performancePrinter.timeSumPrinter, sourceFilePath);
    if (typeof content === 'string') {
      ast = createSourceFile(sourceFilePath, content, ScriptTarget.ES2015, true);
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
      } else {
        //@ts-ignore
        ast.reservedComments ??= this.mCustomProfiles.mRemoveDeclarationComments.mReservedComments ? 
          this.mCustomProfiles.mRemoveDeclarationComments.mReservedComments : [];
      }
    } else {
      //@ts-ignore
      ast.reservedComments = this.mCustomProfiles.mRemoveComments? [] : undefined;
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
        sourceMapJson = await this.mergeSourceMap(previousStageSourceMap, sourceMapJson as sourceMap.RawSourceMap);
      }
      result.sourceMap = sourceMapJson;
      let nameCache = renameIdentifierModule.nameCache;
      if (this.mCustomProfiles.mEnableNameCache) {
        const consumer = await new sourceMap.SourceMapConsumer(sourceMapJson as sourceMap.RawSourceMap);
        let newIdentifierCache: Object = this.convertLineInfoForCache(consumer, IDENTIFIER_CACHE);
        let newMemberMethodCache: Object = this.convertLineInfoForCache(consumer, MEM_METHOD_CACHE);
        nameCache.set(IDENTIFIER_CACHE, newIdentifierCache);
        nameCache.set(MEM_METHOD_CACHE, newMemberMethodCache);
        result.nameCache = {[IDENTIFIER_CACHE]: newIdentifierCache, [MEM_METHOD_CACHE]: newMemberMethodCache};
      }
    }

    // clear cache of text writer
    this.mTextWriter.clear();
    if (renameIdentifierModule.nameCache) {
      renameIdentifierModule.nameCache.clear();
    }

    renameIdentifierModule.historyNameCache = undefined;
    return result;
  }
}

export {ApiExtractor};
