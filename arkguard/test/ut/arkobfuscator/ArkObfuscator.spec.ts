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

import { describe, it } from 'mocha';
import { assert, expect } from 'chai';
import { ArkObfuscator, FileUtils, UnobfuscationCollections, wildcardTransformer } from '../../../src/ArkObfuscator';
import { ArkObfuscatorForTest } from '../../../src/ArkObfuscatorForTest'
import path from 'path';
import { TransformerFactory, Node, SourceFile, createSourceFile, ScriptTarget, Printer, createTextWriter, RawSourceMap } from 'typescript';
import { IOptions } from '../../../src/configs/IOptions';
import { getSourceMapGenerator } from '../../../src/utils/SourceMapUtil';
import fs from 'fs';
import esInfo from '../../../src/configs/preset/es_reserved_properties.json';
import optimizeEsInfo from '../../../src/configs/preset/es_reserved_properties_optimized.json'

describe('Tester Cases for <ArkObfuscatorForTest>.', function () {
  describe('Tester Cases for <ArkObfuscatorForTest>.', function () {
    let etsSourceFile: SourceFile;
    let dEtsSourceFile: SourceFile;
    let tsSourceFile: SourceFile;
    let etsSourceFilePath: string = 'demo.ets';
    let dEtsSourceFilePath: string = 'demo.d.ets';
    let tsSourceFilePath: string = 'demo.ts';

    before('init sourceFile', function () {
      const etsfileContent = `//This is a comment
//This is a comment
//This is a comment
//This is a comment
class Demo{
  constructor(public  title: string, public  content: string, public  mark: number) {
      this.title = title
      this.content = content
      this.mark = mark
  }
}
`;
      const dEtsFileContent = `
      /**
       * This is a comment
       */

      class Demo{
          constructor(public  title: string, public  content: string, public  mark: number) {
              this.title = title
              this.content = content
              this.mark = mark
          }
      }
      `;

      const tsFileContent = `
      //This is a comment
      class Demo{
          constructor(public  title: string, public  content: string, public  mark: number) {
              this.title = title
              this.content = content
              this.mark = mark
          }
      }
      `;

      etsSourceFile = createSourceFile('demo.ts', etsfileContent, ScriptTarget.ES2015, true);
      dEtsSourceFile = createSourceFile(dEtsSourceFilePath, dEtsFileContent, ScriptTarget.ES2015, true);
      tsSourceFile = createSourceFile(tsSourceFilePath, tsFileContent, ScriptTarget.ES2015, true);
    });

    it('Tester: test case for handleTsHarComments for ets file', function () {
      let mCustomProfiles: IOptions | undefined = FileUtils.readFileAsJson(path.join(__dirname, "default_config.json"));
      let arkobfuscator = new ArkObfuscatorForTest();
      arkobfuscator.init(mCustomProfiles);
      let originalFilePath = 'demo.ets';
      ArkObfuscatorForTest.projectInfo = { packageDir: '', projectRootPath: '', localPackageSet: new Set<string>(), useNormalized: false, useTsHar: true };
      arkobfuscator.handleTsHarComments(etsSourceFile, originalFilePath);
      let sourceMapGenerator = getSourceMapGenerator(originalFilePath);
      const textWriter = createTextWriter('\n');
      arkobfuscator.createObfsPrinter(etsSourceFile.isDeclarationFile).writeFile(etsSourceFile, textWriter, sourceMapGenerator);
      const actualContent = textWriter.getText();
      const expectContent = `
      // @keepTs
      // @ts-nocheck
      class Demo {
          constructor(public title: string, public content: string, public mark: number) {
              this.title = title;
              this.content = content;
              this.mark = mark;
          }
      }`;

      let actualSourceMap: RawSourceMap = sourceMapGenerator.toJSON();
      actualSourceMap.sourceRoot = "";
      let expectSourceMap = {
          "version": 3,
          "file": "demo.ets",
          "sourceRoot": "",
          "sources": [
            "demo.ts"
          ],
          "names": [],
          "mappings": ";;AAIA,MAAM,IAAI;IACR,YAAY,MAAM,CAAE,KAAK,EAAE,MAAM,EAAE,MAAM,CAAE,OAAO,EAAE,MAAM,EAAE,MAAM,CAAE,IAAI,EAAE,MAAM;QAC5E,IAAI,CAAC,KAAK,GAAG,KAAK,CAAA;QAClB,IAAI,CAAC,OAAO,GAAG,OAAO,CAAA;QACtB,IAAI,CAAC,IAAI,GAAG,IAAI,CAAA;IACpB,CAAC;CACF"
        }
      assert.strictEqual(compareStringsIgnoreNewlines(actualContent, expectContent), true);
      assert.strictEqual(compareStringsIgnoreNewlines(JSON.stringify(actualSourceMap, null, 2), JSON.stringify(expectSourceMap, null, 2)), true);
    });

    it('Tester: test case for handleTsHarComments for d.ets file', function () {
      let mCustomProfiles: IOptions | undefined = FileUtils.readFileAsJson(path.join(__dirname, "default_config.json"));
      let arkobfuscator = new ArkObfuscatorForTest();
      arkobfuscator.init(mCustomProfiles);
      ArkObfuscatorForTest.projectInfo = { packageDir: '', projectRootPath: '', localPackageSet: new Set<string>(), useNormalized: false, useTsHar: true };
      arkobfuscator.handleTsHarComments(dEtsSourceFile, dEtsSourceFilePath);
      let sourceMapGenerator = getSourceMapGenerator(dEtsSourceFilePath);
      const textWriter = createTextWriter('\n');
      arkobfuscator.createObfsPrinter(dEtsSourceFile.isDeclarationFile).writeFile(dEtsSourceFile, textWriter, sourceMapGenerator);
      const actualContent = textWriter.getText();
      const expectContent = `
      /**
       * This is a comment
       */
      class Demo {
          constructor(public title: string, public content: string, public mark: number) {
              this.title = title;
              this.content = content;
              this.mark = mark;
          }
      }`;
      assert.strictEqual(compareStringsIgnoreNewlines(actualContent, expectContent), true);
    });

    it('Tester: test case for handleTsHarComments for ts file', function () {
      let mCustomProfiles: IOptions | undefined = FileUtils.readFileAsJson(path.join(__dirname, "default_config.json"));
      let arkobfuscator = new ArkObfuscatorForTest();
      arkobfuscator.init(mCustomProfiles);
      ArkObfuscatorForTest.projectInfo = { packageDir: '', projectRootPath: '', localPackageSet: new Set<string>(), useNormalized: false, useTsHar: true };
      arkobfuscator.handleTsHarComments(tsSourceFile, tsSourceFilePath);
      let sourceMapGenerator = getSourceMapGenerator(tsSourceFilePath);
      const textWriter = createTextWriter('\n');
      arkobfuscator.createObfsPrinter(tsSourceFile.isDeclarationFile).writeFile(tsSourceFile, textWriter, sourceMapGenerator);
      const actualContent = textWriter.getText();
      const expectContent = `
        class Demo {
          constructor(public title: string, public content: string, public mark: number) {
            this.title = title;
            this.content = content;
            this.mark = mark;
          }
        }`;
      assert.strictEqual(compareStringsIgnoreNewlines(actualContent, expectContent), true);
    });
  });

  describe('Tester Cases for <ArkObfuscatorForTest>.', function () {
    it('Tester: test case for ArkObfuscatorForTest.ini', function (){
      let configPath = "test/ut/arkobfuscator/iniTestObfConfig.json"
      let obfuscator: ArkObfuscatorForTest = new ArkObfuscatorForTest();
      const originalConfig: IOptions | undefined = FileUtils.readFileAsJson(configPath);
      obfuscator.init(originalConfig);
      let config = obfuscator.customProfiles;
      let reservedTopelevelNames = config.mNameObfuscation?.mReservedToplevelNames;
      let reservedProperty = config.mNameObfuscation?.mReservedProperties;
      let universalReservedToplevelNames = config.mNameObfuscation?.mUniversalReservedToplevelNames as RegExp[];
      let universalReservedProperties = config.mNameObfuscation?.mUniversalReservedProperties as RegExp[];
      assert.isTrue(reservedTopelevelNames?.includes("func2"));
      assert.isTrue(reservedProperty?.includes("prop"));
      assert.equal(universalReservedToplevelNames[0].toString(), new RegExp(`^${wildcardTransformer("a*")}$`).toString());
      assert.equal(universalReservedToplevelNames[1].toString(), new RegExp(`^${wildcardTransformer("*shoul?keep*")}$`).toString());
      assert.equal(universalReservedProperties[0].toString(), new RegExp(`^${wildcardTransformer("prop?")}$`).toString());
      assert.equal(universalReservedProperties[2].toString(), new RegExp(`^${wildcardTransformer("*pro?")}$`).toString());
      assert.equal(universalReservedProperties[1].toString(), new RegExp(`^${wildcardTransformer("function*")}$`).toString());
    });

    it('Tester: test case for ArkObfuscator.ini', function (){
      let configPath = "test/ut/arkobfuscator/iniTestObfConfig.json"
      let obfuscator: ArkObfuscator = new ArkObfuscator();
      let config = FileUtils.readFileAsJson(configPath) as IOptions;
      obfuscator.init(config);
      let reservedTopelevelNames = config.mNameObfuscation?.mReservedToplevelNames;
      let reservedProperty = config.mNameObfuscation?.mReservedProperties;
      let universalReservedToplevelNames = config.mNameObfuscation?.mUniversalReservedToplevelNames;
      let universalReservedProperties = config.mNameObfuscation?.mUniversalReservedProperties;
      assert.isTrue(reservedTopelevelNames?.includes("func2"));
      assert.isTrue(reservedTopelevelNames?.includes("a*"));
      assert.isTrue(reservedTopelevelNames?.includes("*shoul?keep*"));
      assert.isTrue(reservedProperty?.includes("prop"));
      assert.isTrue(reservedProperty?.includes("prop?"));
      assert.isTrue(reservedProperty?.includes("*pro?"));
      assert.isTrue(reservedProperty?.includes("function*"));
      assert.equal(universalReservedToplevelNames, undefined);
      assert.equal(universalReservedProperties, undefined);
    });

    it('Tester: test case for use default preset language whitelist', function (){
      let obfuscator: ArkObfuscator = new ArkObfuscator();
      let config: IOptions = {
        "mNameObfuscation": {
            "mEnable": true,
            "mNameGeneratorType": 1,
            "mDictionaryList": [],
            "mRenameProperties": true,
            "mReservedProperties": [],
            "mKeepStringProperty": false,
            "mTopLevel": true,
            "mReservedToplevelNames": []
        },
        "mEnableSourceMap": false,
        "mEnableNameCache": false,
        "mStripLanguageDefaultWhitelist": false
      };

      obfuscator.init(config);
      let languageSet: Set<string> = new Set();
      let presetLanguageWhitelist = esInfo;
      for (const key of Object.keys(presetLanguageWhitelist)) {
        const valueArray = presetLanguageWhitelist[key];
        valueArray.forEach((element: string) => {
          languageSet.add(element);
        });
      }
      expect(languageSet).to.deep.equal(UnobfuscationCollections.reservedLangForProperty);
    });

    it('Tester: test case for use optimized preset language whitelist', function (){
      let obfuscator: ArkObfuscator = new ArkObfuscator();
      let config: IOptions = {
        "mNameObfuscation": {
            "mEnable": true,
            "mNameGeneratorType": 1,
            "mDictionaryList": [],
            "mRenameProperties": true,
            "mReservedProperties": [],
            "mKeepStringProperty": false,
            "mTopLevel": true,
            "mReservedToplevelNames": []
        },
        "mEnableSourceMap": false,
        "mEnableNameCache": false,
        "mStripLanguageDefaultWhitelist": true
      };

      obfuscator.init(config);
      let languageSet: Set<string> = new Set();
      let presetLanguageWhitelist = optimizeEsInfo;
      for (const key of Object.keys(presetLanguageWhitelist)) {
        const valueArray = presetLanguageWhitelist[key];
        valueArray.forEach((element: string) => {
          languageSet.add(element);
        });
      }
      expect(languageSet).to.deep.equal(UnobfuscationCollections.reservedLangForProperty);
    });
  });
});

function compareStringsIgnoreNewlines(str1: string, str2: string): boolean {
  const normalize = (str: string) => str.replace(/[\n\r\s]+/g, '');
  return normalize(str1) === normalize(str2);
}