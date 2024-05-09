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
import { assert } from 'chai';
import { ArkObfuscator, FileUtils } from '../../../src/ArkObfuscator';
import path from 'path';
import { TransformerFactory, Node, SourceFile, createSourceFile, ScriptTarget, Printer, createTextWriter, RawSourceMap } from 'typescript';
import { IOptions } from '../../../src/configs/IOptions';
import { getSourceMapGenerator } from '../../../src/utils/SourceMapUtil';
import fs from 'fs';

describe('Tester Cases for <ArkObfuscator>.', function () {
  describe('Tester Cases for <ArkObfuscator>.', function () {
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
      let arkobfuscator = new ArkObfuscator();
      arkobfuscator.init(mCustomProfiles);
      let originalFilePath = 'demo.ets';
      ArkObfuscator.projectInfo = { packageDir: '', projectRootPath: '', localPackageSet: new Set<string>(), useNormalized: false, useTsHar: true };
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
      console.log(JSON.stringify(actualSourceMap, null, 2))
      assert.strictEqual(compareStringsIgnoreNewlines(actualContent, expectContent), true);
      assert.strictEqual(compareStringsIgnoreNewlines(JSON.stringify(actualSourceMap, null, 2), JSON.stringify(expectSourceMap, null, 2)), true);
    });

    it('Tester: test case for handleTsHarComments for d.ets file', function () {
      let mCustomProfiles: IOptions | undefined = FileUtils.readFileAsJson(path.join(__dirname, "default_config.json"));
      let arkobfuscator = new ArkObfuscator();
      arkobfuscator.init(mCustomProfiles);
      ArkObfuscator.projectInfo = { packageDir: '', projectRootPath: '', localPackageSet: new Set<string>(), useNormalized: false, useTsHar: true };
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
      let arkobfuscator = new ArkObfuscator();
      arkobfuscator.init(mCustomProfiles);
      ArkObfuscator.projectInfo = { packageDir: '', projectRootPath: '', localPackageSet: new Set<string>(), useNormalized: false, useTsHar: true };
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
      console.log(actualContent)
      assert.strictEqual(compareStringsIgnoreNewlines(actualContent, expectContent), true);
      console.log(actualContent);
    });
  });
});

function compareStringsIgnoreNewlines(str1: string, str2: string): boolean {
  const normalize = (str: string) => str.replace(/[\n\r\s]+/g, '');
  return normalize(str1) === normalize(str2);
}