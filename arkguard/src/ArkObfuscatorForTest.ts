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

import {
  ArkObfuscator,
  ObfuscationResultType,
  PropCollections,
  performancePrinter,
  renameIdentifierModule
} from './ArkObfuscator';
import { readProjectProperties } from './common/ApiReader';
import { FileUtils } from './utils/FileUtils';
import { EventList } from './utils/PrinterUtils';
import { handleReservedConfig } from './utils/TransformUtil';
import {
  IDENTIFIER_CACHE,
  NAME_CACHE_SUFFIX,
  PROPERTY_CACHE_FILE,
  deleteLineInfoForNameString,
  getMapFromJson,
  readCache,
  writeCache
} from './utils/NameCacheUtil';

import * as fs from 'fs';
import path from 'path';
import filterFileArray from './configs/test262filename/filterFilenameList.json';

import type { IOptions } from './configs/IOptions';

const JSON_TEXT_INDENT_LENGTH: number = 2;

export class ArkObfuscatorForTest extends ArkObfuscator {
  // A list of source file path
  private readonly mSourceFiles: string[];

  // Path of obfuscation configuration file.
  private readonly mConfigPath: string;

  constructor(sourceFiles?: string[], configPath?: string) {
    super();
    this.mSourceFiles = sourceFiles;
    this.mConfigPath = configPath;
  }

  public get configPath(): string {
    return this.mConfigPath;
  }

  /**
   * init ArkObfuscator according to user config
   * should be called after constructor
   */
  public init(config: IOptions | undefined): boolean {
    if (!config) {
        console.error('obfuscation config file is not found and no given config.');
        return false;
    }

    handleReservedConfig(config, 'mNameObfuscation', 'mReservedProperties', 'mUniversalReservedProperties');
    handleReservedConfig(config, 'mNameObfuscation', 'mReservedToplevelNames', 'mUniversalReservedToplevelNames');
    return super.init(config)
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

    const test262Filename = this.getPathAfterTest262SecondLevel(sourceFilePath);
    const isFileInArray = filterFileArray.includes(test262Filename);
    // To skip the path where 262 test will fail.
    if (isFileInArray) {
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

  private getPathAfterTest262SecondLevel(fullPath) {
    const pathParts = fullPath.split('/');
    const dataIndex = pathParts.indexOf('test262');
    // If it is not the directory of test262, return to the original path.
    if (dataIndex === -1) {
      return fullPath;
    }

    // 2: Calculate the index of the second-level directory after 'test262'
    const secondLevelIndex = dataIndex + 2;
    if (secondLevelIndex < pathParts.length) {
      return pathParts.slice(secondLevelIndex).join('/');
    }
  }

  private produceNameCache(namecache: { [k: string]: string | {} }, resultPath: string): void {
    const nameCachePath: string = resultPath + NAME_CACHE_SUFFIX;
    fs.writeFileSync(nameCachePath, JSON.stringify(namecache, null, JSON_TEXT_INDENT_LENGTH));
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

  private producePropertyCache(outputDir: string): void {
    if (this.mCustomProfiles.mNameObfuscation &&
      this.mCustomProfiles.mNameObfuscation.mRenameProperties &&
      this.mCustomProfiles.mEnableNameCache) {
      const propertyCachePath: string = path.join(outputDir, PROPERTY_CACHE_FILE);
      writeCache(PropCollections.globalMangledTable, propertyCachePath);
    }
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

    PropCollections.historyMangledTable = getMapFromJson(propertyCache);
  }
}