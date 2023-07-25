/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
  getMapFromJson,
  NAME_CACHE_SUFFIX,
  PROPERTY_CACHE_FILE,
  readCache, writeCache
} from './utils/NameCacheUtil';
import {ListUtil} from './utils/ListUtil';
import {needReadApiInfo, readProjectProperties} from './common/ApiReader';
import {ApiExtractor} from './common/ApiExtractor';
import es6Info from './configs/preset/es6_reserved_properties.json';

export const renameIdentifierModule = require('./transformers/rename/RenameIdentifierTransformer');
export const renamePropertyModule = require('./transformers/rename/RenamePropertiesTransformer');

export {getMapFromJson, readProjectProperties};

type ObfuscationResultType = {
  content: string,
  sourceMap?: RawSourceMap,
  nameCache?: { [k: string]: string }
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

  public constructor(sourceFiles?: string[], configPath?: string) {
    this.mSourceFiles = sourceFiles;
    this.mConfigPath = configPath;
    this.mCompilerOptions = {};
    this.mTransformers = [];
  }

  /**
   * init ArkObfuscator according to user config
   * should be called after constructor
   */
  public init(config?: IOptions): boolean {
    if (!this.mConfigPath && !config) {
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

    // load transformers
    this.mTransformers = TransformerManager.getInstance().loadTransformers(this.mCustomProfiles);

    if (needReadApiInfo(this.mCustomProfiles)) {
      this.mCustomProfiles.mNameObfuscation.mReservedProperties = ListUtil.uniqueMergeList(
        this.mCustomProfiles.mNameObfuscation.mReservedProperties,
        this.mCustomProfiles.mNameObfuscation.mReservedNames,
        es6Info);
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
  }

  /**
   * obfuscate directory
   * @private
   */
  private async obfuscateDir(dirName: string, dirPrefix: string): Promise<void> {
    const currentDir: string = FileUtils.getPathWithoutPrefix(dirName, dirPrefix);
    const newDir: string = path.join(this.mCustomProfiles.mOutputDir, currentDir);
    if (!fs.existsSync(newDir)) {
      fs.mkdirSync(newDir);
    }

    const fileNames: string[] = fs.readdirSync(dirName);
    for (let fileName of fileNames) {
      const filePath: string = path.join(dirName, fileName);
      if (fs.lstatSync(filePath).isFile()) {
        await this.obfuscateFile(filePath, newDir);
        continue;
      }

      if (fileName === 'node_modules' || fileName === 'oh_modules') {
        continue;
      }

      await this.obfuscateDir(filePath, dirPrefix);
    }
  }

  private readNameCache(sourceFile: string, outputDir: string): void {
    if (!this.mCustomProfiles.mNameObfuscation.mEnable || !this.mCustomProfiles.mEnableNameCache) {
      return;
    }

    const nameCachePath: string = path.join(outputDir, FileUtils.getFileName(sourceFile) + NAME_CACHE_SUFFIX);
    const nameCache: Object = readCache(nameCachePath);

    renameIdentifierModule.historyNameCache = getMapFromJson(nameCache);
  }

  private readPropertyCache(outputDir: string): void {
    if (!this.mCustomProfiles.mNameObfuscation.mRenameProperties || !this.mCustomProfiles.mEnableNameCache) {
      return;
    }

    const propertyCachePath: string = path.join(outputDir, PROPERTY_CACHE_FILE);
    const propertyCache: Object = readCache(propertyCachePath);
    if (!propertyCache) {
      return;
    }

    renamePropertyModule.historyMangledTable = getMapFromJson(propertyCache);
  }

  private produceNameCache(namecache: { [k: string]: string }, sourceFile: string, outputDir: string): void {
    const nameCachePath: string = path.join(outputDir, FileUtils.getFileName(sourceFile) + NAME_CACHE_SUFFIX);
    fs.writeFileSync(nameCachePath, JSON.stringify(namecache, null, JSON_TEXT_INDENT_LENGTH));
  }

  private producePropertyCache(outputDir: string): void {
    if (this.mCustomProfiles.mNameObfuscation.mRenameProperties && this.mCustomProfiles.mEnableNameCache) {
      const propertyCachePath: string = path.join(outputDir, PROPERTY_CACHE_FILE);
      writeCache(renamePropertyModule.globalMangledTable, propertyCachePath);
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
  public createObfsPrinter(): Printer {
    // set print options
    let printerOptions: PrinterOptions = {};
    if (this.mCustomProfiles.mRemoveComments) {
      printerOptions.removeComments = true;
    }

    return createPrinter(printerOptions);
  }

  private isObfsIgnoreFile(fileName: string): boolean {
    let suffix: string = FileUtils.getFileExtension(fileName);

    return (suffix !== 'js' && suffix !== 'ts') || fileName.endsWith('.d.ts');
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

    let content: string = FileUtils.readFile(sourceFilePath);
    this.readNameCache(sourceFilePath, outputDir);
    const mixedInfo: ObfuscationResultType = await this.obfuscate(content, sourceFilePath);

    if (outputDir && mixedInfo) {
      fs.writeFileSync(path.join(outputDir, FileUtils.getFileName(sourceFilePath)), mixedInfo.content);
      if (this.mCustomProfiles.mEnableSourceMap && mixedInfo.sourceMap) {
        fs.writeFileSync(path.join(outputDir, FileUtils.getFileName(sourceFilePath) + '.map'),
          JSON.stringify(mixedInfo.sourceMap, null, JSON_TEXT_INDENT_LENGTH));
      }
      if (this.mCustomProfiles.mEnableNameCache && this.mCustomProfiles.mEnableNameCache) {
        this.produceNameCache(mixedInfo.nameCache, sourceFilePath, outputDir);
      }
    }
  }

  /**
   * Obfuscate ast of a file.
   * @param content ast or source code of a source file
   * @param sourceFilePath
   * @param previousStageSourceMap
   * @param historyNameCache
   */
  public async obfuscate(content: SourceFile | string, sourceFilePath: string, previousStageSourceMap?: sourceMap.RawSourceMap, 
    historyNameCache?: Map<string, string>): Promise<ObfuscationResultType> {
    let ast: SourceFile;
    let result: ObfuscationResultType = { content: undefined };
    if (this.isObfsIgnoreFile(sourceFilePath)) {
      // need add return value
      return result;
    }

    if (typeof content === 'string') {
      ast = createSourceFile(sourceFilePath, content, ScriptTarget.ES2015, true);
    } else {
      ast = content;
    }

    if (ast.statements.length === 0) {
      return result;
    }

    if (historyNameCache && this.mCustomProfiles.mNameObfuscation) {
      renameIdentifierModule.historyNameCache = historyNameCache;
    }

    let transformedResult: TransformationResult<Node> = transform(ast, this.mTransformers, this.mCompilerOptions);
    ast = transformedResult.transformed[0] as SourceFile;

    // convert ast to output source file and generate sourcemap if needed.
    let sourceMapGenerator: SourceMapGenerator = undefined;
    if (this.mCustomProfiles.mEnableSourceMap) {
      sourceMapGenerator = getSourceMapGenerator(sourceFilePath);
    }

    this.createObfsPrinter().writeFile(ast, this.mTextWriter, sourceMapGenerator);

    result.content = this.mTextWriter.getText();

    if (this.mCustomProfiles.mEnableSourceMap && sourceMapGenerator) {
      let sourceMapJson: RawSourceMap = sourceMapGenerator.toJSON();
      sourceMapJson.sourceRoot = '';
      sourceMapJson.file = path.basename(sourceFilePath);
      if (previousStageSourceMap) {
        sourceMapJson = await this.mergeSourceMap(previousStageSourceMap, sourceMapJson as sourceMap.RawSourceMap);
      }
      result.sourceMap = sourceMapJson;
    }

    if (this.mCustomProfiles.mEnableNameCache) {
      result.nameCache = Object.fromEntries(renameIdentifierModule.nameCache);
    }

    // clear cache of text writer
    this.mTextWriter.clear();
    if (renameIdentifierModule.nameCache) {
      renameIdentifierModule.nameCache.clear();
    }
    return result;
  }
}
export {ApiExtractor};
