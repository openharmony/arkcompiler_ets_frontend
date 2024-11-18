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
import { IOptions } from '../../../src/configs/IOptions';
import { FileUtils } from '../../../src/utils/FileUtils';
import { ArkObfuscatorForTest } from '../../../src/ArkObfuscatorForTest'
import secharmony, {
  transformerPlugin,
  historyNameCache,
  clearCaches,
 } from '../../../src/transformers/rename/RenameIdentifierTransformer';
import path from 'path';
import * as ts from 'typescript';
import {
  PropCollections,
  UnobfuscationCollections,
  LocalVariableCollections
} from '../../../src/utils/CommonCollections';

describe('Teste Cases for <RenameFileNameTransformer>.', function () {
  describe('Teste Cases for <createRenameIdentifierFactory>.', function () {
    it('should return null if mEnable is false',function () {
      let options: IOptions = {
        "mNameObfuscation": {
          "mEnable": false,
          "mRenameProperties": false,
          "mReservedProperties": []
        }
      };
      let renameIdentifierFactory = transformerPlugin.createTransformerFactory(options);
      expect(renameIdentifierFactory).to.be.null;
    })
    describe('Teste Cases for <renameTransformer>.', function () {
      let option: IOptions = {
        "mCompact": false,
        "mRemoveComments": false,
        "mOutputDir": "",
        "mDisableConsole": false,
        "mSimplify": false,
        "mNameObfuscation": {
            "mEnable": true,
            "mNameGeneratorType": 1,
            "mDictionaryList": [],
            "mRenameProperties": true,
            "mKeepStringProperty": false,
            "mTopLevel": false,
            "mReservedProperties": []
        },
        "mEnableSourceMap": true,
        "mEnableNameCache": true
      };
      const fileContent = `
      class A1{
        prop_5 = 5;
        constructor(public para1: number, private para2: string, protected para3: boolean, readonly para4: number, para5: string) {
          para5 = para5 + 1;
          let temp1 = para1;
          let temp2 = para2;
          let temp3 = para3;
          let temp4 = para4;
          this.prop_5 = para4;
        }
      }
      `;
      const fileContent1 = `
      class a{
        prop_5 = 5;
        constructor(public para1: number, private para2: string, protected para3: boolean, readonly para4: number, para5: string) {
          para5 = para5 + 1;
          let temp1 = para1;
          let temp2 = para2;
          let temp3 = para3;
          let temp4 = para4;
          this.prop_5 = para4;
        }
      }
      `;
      const fileContent2 = `
      import {A as B} from './file1.ts';
      export {C as D} from './file1.ts';
      `;
      let transformer: ts.TransformerFactory<ts.Node>;

      it('should not transform parameter property when mRenameProperties is false',function () {
        let option1: IOptions = {
          "mCompact": false,
          "mRemoveComments": false,
          "mOutputDir": "",
          "mDisableConsole": false,
          "mSimplify": false,
          "mNameObfuscation": {
              "mEnable": true,
              "mNameGeneratorType": 1,
              "mDictionaryList": [],
              "mRenameProperties": false,
              "mKeepStringProperty": false,
              "mTopLevel": false,
              "mReservedProperties": []
          },
          "mEnableSourceMap": true,
          "mEnableNameCache": true
        };
        transformer = transformerPlugin.createTransformerFactory(option1);
        const sourceFile: ts.SourceFile = ts.createSourceFile('demo.ts', fileContent, ts.ScriptTarget.ES2015, true);
        let transformed = ts.transform(sourceFile, [transformer]);
        expect(
          ((((transformed
            .transformed[0] as ts.SourceFile)
            .statements[0] as ts.ClassDeclaration)
            .members[1] as ts.ConstructorDeclaration)
            .parameters[0]
            .name as ts.Identifier)
            .escapedText == 'para1')
            .to.be.true;
        expect(
          ((((transformed
            .transformed[0] as ts.SourceFile)
            .statements[0] as ts.ClassDeclaration)
            .members[1] as ts.ConstructorDeclaration)
            .parameters[1]
            .name as ts.Identifier)
            .escapedText == 'para2')
            .to.be.true;
        expect(
          ((((transformed
            .transformed[0] as ts.SourceFile)
            .statements[0] as ts.ClassDeclaration)
            .members[1] as ts.ConstructorDeclaration)
            .parameters[2]
            .name as ts.Identifier)
            .escapedText == 'para3')
            .to.be.true;
        expect(
          ((((transformed
            .transformed[0] as ts.SourceFile)
            .statements[0] as ts.ClassDeclaration)
            .members[1] as ts.ConstructorDeclaration)
            .parameters[3]
            .name as ts.Identifier)
            .escapedText == 'para4')
            .to.be.true;
        expect(
          ((((transformed
            .transformed[0] as ts.SourceFile)
            .statements[0] as ts.ClassDeclaration)
            .members[1] as ts.ConstructorDeclaration)
            .parameters[4]
            .name as ts.Identifier)
            .escapedText == 'a')
            .to.be.true;
      })

      it('should not transform parameter property when mRenameProperties is true',function () {
        transformer = transformerPlugin.createTransformerFactory(option);
        const sourceFile: ts.SourceFile = ts.createSourceFile('demo.ts', fileContent, ts.ScriptTarget.ES2015, true);
        let transformed = ts.transform(sourceFile, [transformer]);
        expect(
          ((((transformed
            .transformed[0] as ts.SourceFile)
            .statements[0] as ts.ClassDeclaration)
            .members[1] as ts.ConstructorDeclaration)
            .parameters[0].name as ts.Identifier)
            .escapedText == 'a')
            .to.be.true;
        expect(
          ((((transformed
            .transformed[0] as ts.SourceFile)
            .statements[0] as ts.ClassDeclaration)
            .members[1] as ts.ConstructorDeclaration)
            .parameters[1]
            .name as ts.Identifier)
            .escapedText == 'b')
            .to.be.true;
        expect(
          ((((transformed
            .transformed[0] as ts.SourceFile)
            .statements[0] as ts.ClassDeclaration)
            .members[1] as ts.ConstructorDeclaration)
            .parameters[2]
            .name as ts.Identifier)
            .escapedText == 'c')
            .to.be.true;
        expect(
          ((((transformed
            .transformed[0] as ts.SourceFile)
            .statements[0] as ts.ClassDeclaration)
            .members[1] as ts.ConstructorDeclaration)
            .parameters[3]
            .name as ts.Identifier)
            .escapedText == 'd')
            .to.be.true;
        expect(
          ((((transformed
            .transformed[0] as ts.SourceFile)
            .statements[0] as ts.ClassDeclaration)
            .members[1] as ts.ConstructorDeclaration)
            .parameters[4]
            .name as ts.Identifier)
            .escapedText == 'e')
            .to.be.true;
      })

      it('should use historyMangledName when originName is in historyMangledTable', function () {
        PropCollections.historyMangledTable.set('para1', 'test1');
        PropCollections.globalMangledTable.set('para1', 'test2');
        transformer = transformerPlugin.createTransformerFactory(option);
        const sourceFile: ts.SourceFile = ts.createSourceFile('demo.ts', fileContent, ts.ScriptTarget.ES2015, true);
        let transformed = ts.transform(sourceFile, [transformer]);
        expect(
          ((((transformed
            .transformed[0] as ts.SourceFile)
            .statements[0] as ts.ClassDeclaration)
            .members[1] as ts.ConstructorDeclaration)
            .parameters[0]
            .name as ts.Identifier)
            .escapedText == 'test1')
            .to.be.true;
        PropCollections.historyMangledTable.clear();
        PropCollections.globalMangledTable.clear();
      })

      it('should use historyMangledName when originName is in globalMangleTable', function () {
        PropCollections.globalMangledTable.set('para1', 'test2');
        transformer = transformerPlugin.createTransformerFactory(option);
        const sourceFile: ts.SourceFile = ts.createSourceFile('demo.ts', fileContent, ts.ScriptTarget.ES2015, true);
        let transformed = ts.transform(sourceFile, [transformer]);
        expect(
          ((((transformed
            .transformed[0] as ts.SourceFile)
            .statements[0] as ts.ClassDeclaration)
            .members[1] as ts.ConstructorDeclaration)
            .parameters[0]
            .name as ts.Identifier)
            .escapedText == 'test2')
            .to.be.true;
        PropCollections.globalMangledTable.clear();
      })

      it('should not obfuscate when originName is in property whitelist', function () {
        PropCollections.reservedProperties.add('para1');
        transformer = transformerPlugin.createTransformerFactory(option);
        const sourceFile: ts.SourceFile = ts.createSourceFile('demo.ts', fileContent, ts.ScriptTarget.ES2015, true);
        let transformed = ts.transform(sourceFile, [transformer]);
        expect(
          ((((transformed
            .transformed[0] as ts.SourceFile)
            .statements[0] as ts.ClassDeclaration)
            .members[1] as ts.ConstructorDeclaration)
            .parameters[0].name as ts.Identifier)
            .escapedText == 'para1')
            .to.be.true;
        PropCollections.reservedProperties.clear();
        PropCollections.newlyOccupiedMangledProps.clear();
        PropCollections.globalMangledTable.clear();
      })

      it('should not obfuscated as names in ReservedProperty or ReservedLocalVariable or newlyOccupiedMangledProps or mangledPropsInNameCache', function () {
        PropCollections.reservedProperties.add('b');
        UnobfuscationCollections.reservedExportName.add('c');
        PropCollections.newlyOccupiedMangledProps.add('d');
        PropCollections.historyMangledTable.set('testorigin', 'e');
        transformer = transformerPlugin.createTransformerFactory(option);
        const sourceFile: ts.SourceFile = ts.createSourceFile('demo.ts', fileContent, ts.ScriptTarget.ES2015, true);
        let transformed = ts.transform(sourceFile, [transformer]);
        expect(
          ((((transformed
            .transformed[0] as ts.SourceFile)
            .statements[0] as ts.ClassDeclaration)
            .members[1] as ts.ConstructorDeclaration)
            .parameters[0]
            .name as ts.Identifier)
            .escapedText == 'a')
            .to.be.true;
        expect(
          ((((transformed
            .transformed[0] as ts.SourceFile)
            .statements[0] as ts.ClassDeclaration)
            .members[1] as ts.ConstructorDeclaration)
            .parameters[1]
            .name as ts.Identifier)
            .escapedText == 'f')
            .to.be.true;
        expect(
          ((((transformed
            .transformed[0] as ts.SourceFile)
            .statements[0] as ts.ClassDeclaration)
            .members[1] as ts.ConstructorDeclaration)
            .parameters[2]
            .name as ts.Identifier)
            .escapedText == 'g')
            .to.be.true;
        expect(
          ((((transformed
            .transformed[0] as ts.SourceFile)
            .statements[0] as ts.ClassDeclaration)
            .members[1] as ts.ConstructorDeclaration)
            .parameters[3]
            .name as ts.Identifier)
            .escapedText == 'h')
            .to.be.true;
        expect(
          ((((transformed
            .transformed[0] as ts.SourceFile)
            .statements[0] as ts.ClassDeclaration)
            .members[1] as ts.ConstructorDeclaration)
            .parameters[4]
            .name as ts.Identifier)
            .escapedText == 'i')
            .to.be.true;
        PropCollections.reservedProperties.clear();
        UnobfuscationCollections.reservedExportName.clear();
        PropCollections.newlyOccupiedMangledProps.clear();
        PropCollections.globalMangledTable.clear();
        UnobfuscationCollections.reservedExportNameAndProp.clear();
        PropCollections.historyMangledTable.clear();
      })

      it('should not obfuscated as names in outer scope', function () {
        transformer = transformerPlugin.createTransformerFactory(option);
        const sourceFile: ts.SourceFile = ts.createSourceFile('demo.ts', fileContent1, ts.ScriptTarget.ES2015, true);
        let transformed = ts.transform(sourceFile, [transformer]);
        expect(
          ((((transformed
            .transformed[0] as ts.SourceFile)
            .statements[0] as ts.ClassDeclaration)
            .members[1] as ts.ConstructorDeclaration)
            .parameters[0]
            .name as ts.Identifier)
            .escapedText == 'b')
            .to.be.true;
        expect(
          ((((transformed
            .transformed[0] as ts.SourceFile)
            .statements[0] as ts.ClassDeclaration)
            .members[1] as ts.ConstructorDeclaration)
            .parameters[1]
            .name as ts.Identifier)
            .escapedText == 'c')
            .to.be.true;
        expect(
          ((((transformed
            .transformed[0] as ts.SourceFile)
            .statements[0] as ts.ClassDeclaration)
            .members[1] as ts.ConstructorDeclaration)
            .parameters[2]
            .name as ts.Identifier)
            .escapedText == 'd')
            .to.be.true;
        expect(
          ((((transformed
            .transformed[0] as ts.SourceFile)
            .statements[0] as ts.ClassDeclaration)
            .members[1] as ts.ConstructorDeclaration)
            .parameters[3]
            .name as ts.Identifier)
            .escapedText == 'e')
            .to.be.true;
        expect(
          ((((transformed
            .transformed[0] as ts.SourceFile)
            .statements[0] as ts.ClassDeclaration)
            .members[1] as ts.ConstructorDeclaration)
            .parameters[4]
            .name as ts.Identifier)
            .escapedText == 'f')
            .to.be.true;
        PropCollections.newlyOccupiedMangledProps.clear();
        PropCollections.globalMangledTable.clear();
      })

      it('Only Enable Toplevel Obfuscation Test', () => {
        let options: IOptions = {
          "mNameObfuscation": {
            "mEnable": true,
            "mRenameProperties": false,
            "mReservedProperties": [],
            "mTopLevel": true
          }
        };
        assert.strictEqual(options !== undefined, true);
        const renameIdentifierFactory = secharmony.transformerPlugin.createTransformerFactory(options);
        const fileContent = `
          let a = 1;
          export let b = 1;
          import {c} from 'filePath';
        `;
        const sourceFile: ts.SourceFile = ts.createSourceFile('demo.ts', fileContent, ts.ScriptTarget.ES2015, true);
        let transformedResult: ts.TransformationResult<ts.Node> = ts.transform(sourceFile, [renameIdentifierFactory], {});
        let ast: ts.SourceFile = transformedResult.transformed[0] as ts.SourceFile;
        const textWriter = ts.createTextWriter('\n');
        let arkobfuscator = new ArkObfuscatorForTest();
        arkobfuscator.init(options);
        arkobfuscator.createObfsPrinter(ast.isDeclarationFile).writeFile(ast, textWriter, undefined);
        const actualContent = textWriter.getText();
        const expectContent = `
          let d = 1;
          export let b = 1;
          import {c} from 'filePath';
        `;
        assert.strictEqual(compareStringsIgnoreNewlines(actualContent, expectContent), true);
      })

      it('should return origin node if isSourceFile is false', () => {
        let options: IOptions | undefined = FileUtils.readFileAsJson(path.join(__dirname, "obfuscate_identifier_config.json"));
        assert.strictEqual(options !== undefined, true);
        const renameIdentifierFactory = secharmony.transformerPlugin.createTransformerFactory(options as IOptions);
        const blockFile: ts.Block = ts.factory.createBlock([]);
        let transformedResult: ts.TransformationResult<ts.Node> = ts.transform(blockFile, [renameIdentifierFactory], {});
        assert.strictEqual(transformedResult.transformed[0], blockFile);
      })

      it('noSymbolIdentifierTest: enable export obfuscation', function () {
        let option1: IOptions = {
          mCompact: false,
          mRemoveComments: false,
          mOutputDir: '',
          mDisableConsole: false,
          mSimplify: false,
          mNameObfuscation: {
            mEnable: true,
            mNameGeneratorType: 1,
            mDictionaryList: [],
            mRenameProperties: false,
            mKeepStringProperty: false,
            mTopLevel: false,
            mReservedProperties: [],
          },
          mExportObfuscation: true,
          mEnableSourceMap: false,
          mEnableNameCache: false,
        };
        transformer = transformerPlugin.createTransformerFactory(option1);
        const sourceFile: ts.SourceFile = ts.createSourceFile('demo.ts', fileContent2, ts.ScriptTarget.ES2015, true);
        let transformed = ts.transform(sourceFile, [transformer]);
        let ast: ts.SourceFile = transformed.transformed[0] as ts.SourceFile;
        const printer = ts.createPrinter();
        const transformedAst: string = printer.printFile(ast);
        expect(transformedAst === "import { A as B } from './file1.ts';\nexport { C as D } from './file1.ts';\n").to.be.true;
      });

      it('noSymbolIdentifierTest: enable export and toplevel obfuscation', function () {
        let option1: IOptions = {
          mCompact: false,
          mRemoveComments: false,
          mOutputDir: '',
          mDisableConsole: false,
          mSimplify: false,
          mNameObfuscation: {
            mEnable: true,
            mNameGeneratorType: 1,
            mDictionaryList: [],
            mRenameProperties: false,
            mKeepStringProperty: false,
            mTopLevel: true,
            mReservedProperties: [],
          },
          mExportObfuscation: true,
          mEnableSourceMap: false,
          mEnableNameCache: false,
        };
        transformer = transformerPlugin.createTransformerFactory(option1);
        const sourceFile: ts.SourceFile = ts.createSourceFile('demo.ts', fileContent2, ts.ScriptTarget.ES2015, true);
        let transformed = ts.transform(sourceFile, [transformer]);
        let ast: ts.SourceFile = transformed.transformed[0] as ts.SourceFile;
        const printer = ts.createPrinter();
        const transformedAst: string = printer.printFile(ast);
        expect(transformedAst === "import { c as a } from './file1.ts';\nexport { e as b } from './file1.ts';\n").to.be.true;
      });
    })
  })
})

function compareStringsIgnoreNewlines(str1: string, str2: string): boolean {
  const normalize = (str: string) => str.replace(/[\n\r\s]+/g, '');
  return normalize(str1) === normalize(str2);
}