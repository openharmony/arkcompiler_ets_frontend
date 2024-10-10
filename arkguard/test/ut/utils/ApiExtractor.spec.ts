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

import { ApiExtractor } from '../../../src/common/ApiExtractor';
import {assert} from 'chai';
import { readProjectPropertiesByCollectedPaths } from '../../../src/common/ApiReader';
import { NameGeneratorType } from '../../../src/generator/NameFactory';

function collectApi(apiPath: string): void {
  clearAll();
  ApiExtractor.traverseApiFiles(apiPath, ApiExtractor.ApiType.API);
}

function clearAll(): void {
  ApiExtractor.mPropertySet.clear();
  ApiExtractor.mSystemExportSet.clear();
}

describe('test for ApiExtractor', function () {
  describe('test for visitExport', function () {
    it('export {ExportDeclarationClass1, ExportDeclarationClass2}', function () {
      let exportDeclarationAst: string = 'test/ut/utils/apiTest_visitExport/exportDeclarationAst.d.ts';
      collectApi(exportDeclarationAst);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('ExportDeclarationClass1'), true);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('ExportDeclarationClass2'), true);
      clearAll();
    });

    it('export {ExportDeclarationClass1 as class1, ExportDeclarationClass2} from `./exportDeclarationFrom`',
     function () {
      let exportDeclarationFromAst: string = 'test/ut/utils/apiTest_visitExport/exportDeclarationFrom.d.ts';
      collectApi(exportDeclarationFromAst);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('ExportDeclarationClass1'), false);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('class1'), true);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('ExportDeclarationClass2'), true);
      clearAll();
    });

    it('export {default as name1, ExportDeclarationClass2, exportName} from `./exportDefaultDeclarationAst`',
     function () {
      let exportDeclarationDefault: string = 'test/ut/utils/apiTest_visitExport/exportDeclarationDefault.d.ts';
      collectApi(exportDeclarationDefault);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('default'), false);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('name1'), true);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('ExportDeclarationClass2'), true);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('exportName'), true);
      clearAll();
    });

    it('export {ExportDeclarationClass1 as exportName, ExportDeclarationClass2, ExportDeclarationClass3 as default}',
     function () {
      let exportDefaultDeclarationAst: string = 'test/ut/utils/apiTest_visitExport/exportDefaultDeclarationAst.d.ts';
      collectApi(exportDefaultDeclarationAst);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('ExportDeclarationClass1'), false);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('exportName'), true);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('ExportDeclarationClass2'), true);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('ExportDeclarationClass3'), false);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('default'), true);
      clearAll();
    });

    it('export * as name1', function () {
      let exportAllAst: string = 'test/ut/utils/apiTest_visitExport/exportAll.d.ts';
      collectApi(exportAllAst);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('name1'), true);
      clearAll();
    });

    it('export * from `export*.ts`', function () {
      let exportFile: string = 'test/ut/utils/apiTest_visitExport/export.d.ts';
      collectApi(exportFile);
      assert.strictEqual(ApiExtractor.mSystemExportSet.size === 0, true);
      assert.strictEqual(ApiExtractor.mPropertySet.size === 0, true);
      clearAll();
    });

    it('doubleUnderscoreTest', function () {
      let doubleUnderscoreTestAst: string = 'test/ut/utils/apiTest_visitExport/doubleUnderscoreTest.d.ts';
      collectApi(doubleUnderscoreTestAst);
      assert.strictEqual(ApiExtractor.mPropertySet.has('__Admin'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('___Admin'), false);
      assert.strictEqual(ApiExtractor.mPropertySet.has('__Moderator'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('___Moderator'), false);
      assert.strictEqual(ApiExtractor.mPropertySet.has('__User'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('___User'), false);
      assert.strictEqual(ApiExtractor.mPropertySet.has('__name'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('___name'), false);
      assert.strictEqual(ApiExtractor.mPropertySet.has('__Admin'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('___Admin'), false);
      assert.strictEqual(ApiExtractor.mPropertySet.has('__age'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('___age'), false);
      assert.strictEqual(ApiExtractor.mPropertySet.has('__greet'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('___greet'), false);
      assert.strictEqual(ApiExtractor.mPropertySet.has('__typeProp1'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('___typeProp1'), false);
      assert.strictEqual(ApiExtractor.mPropertySet.has('__typeProp2'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('___typeProp2'), false);
      assert.strictEqual(ApiExtractor.mPropertySet.has('__speak'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('___speak'), false);
      assert.strictEqual(ApiExtractor.mPropertySet.has('__appName'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('___appName'), false);
      assert.strictEqual(ApiExtractor.mPropertySet.has('__version'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('___version'), false);
      assert.strictEqual(ApiExtractor.mPropertySet.has('__logDetails'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('___logDetails'), false);
      clearAll();
    });
  });

  describe('test for visitPropertyAndName', function () {
    it('Class Test', function () {
      let filePath: string = 'test/ut/utils/apiTest_visitPropertyAndName/classTest.d.ts';
      collectApi(filePath);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('TestClass1'), true);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('TestClass2'), false);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('AbstractClass'), false);
      assert.strictEqual(ApiExtractor.mPropertySet.has('prop1'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('prop2'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('abstractProp'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('foo1'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('foo2'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('param1'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('param2'), false);
      clearAll();
    });

    it('Interface Test', function () {
      let filePath: string = 'test/ut/utils/apiTest_visitPropertyAndName/interfaceTest.d.ts';
      collectApi(filePath);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('TestInterface1'), true);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('TestInterface2'), false);
      assert.strictEqual(ApiExtractor.mPropertySet.has('prop1'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('prop2'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('foo1'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('foo2'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('param1'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('param2'), false);
      clearAll();
    });

    it('TypeLiteral Test', function () {
      let filePath: string = 'test/ut/utils/apiTest_visitPropertyAndName/typeLiteralTest.d.ts';
      collectApi(filePath);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('TestType1'), true);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('TestType2'), false);
      assert.strictEqual(ApiExtractor.mPropertySet.has('collectProp1'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('collectProp2'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('testFunc1'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('testFunc2'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('message1'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('message2'), false);
      clearAll();
    });

    it('Enum Test', function () {
      let filePath: string = 'test/ut/utils/apiTest_visitPropertyAndName/enumTest.d.ts';
      collectApi(filePath);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('TestEnum1'), true);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('TestEnum2'), false);
      assert.strictEqual(ApiExtractor.mPropertySet.has('PARAM1'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('PARAM2'), true);
      clearAll();
    });

    it('ObjectLiteral Test', function () {
      let filePath: string = 'test/ut/utils/apiTest_visitPropertyAndName/objectLiteral.d.ts';
      collectApi(filePath);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('obj1'), true);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('obj2'), false);
      assert.strictEqual(ApiExtractor.mPropertySet.has('prop1'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('prop2'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('prop3'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('prop4'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('innerProp1'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('innerProp2'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('innerProp3'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('innerProp4'), true);
      clearAll();
    });

    it('Module Test', function () {
      let filePath: string = 'test/ut/utils/apiTest_visitPropertyAndName/moduleTest.d.ts';
      collectApi(filePath);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('ns1'), true);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('ns2'), false);
      assert.strictEqual(ApiExtractor.mPropertySet.has('TestClass1'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('TestInterface1'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('prop1'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('prop2'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('prop3'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('TestClass2'), false);
      assert.strictEqual(ApiExtractor.mPropertySet.has('TestInterface2'), false);
      assert.strictEqual(ApiExtractor.mPropertySet.has('prop4'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('prop5'), true);
      clearAll();
    });
  });

  describe('test for visitProjectExport', function () {
    const fileList: Set<string> = new Set([
      "test/ut/utils/module_exports_test/exportFile1.js",
      "test/ut/utils/oh_modules/exportFile.js"
    ]);
    it('test for module.exports(property)', function () {
      let projectAndLibs = readProjectPropertiesByCollectedPaths(fileList,
        {
          mNameObfuscation: {
            mEnable: true,
            mReservedProperties: [],
            mRenameProperties: true,
            mKeepStringProperty: false,
            mNameGeneratorType: NameGeneratorType.ORDERED,
            mReservedNames: [], 
            mReservedToplevelNames: []
          },
          mExportObfuscation: false,
          mKeepFileSourceCode: {
            mKeepSourceOfPaths: new Set(),
            mkeepFilesAndDependencies: new Set(),
          }
        }, true);
      let reservedProperties = projectAndLibs.projectAndLibsReservedProperties == undefined? [] : projectAndLibs.projectAndLibsReservedProperties;
      let reservedExportNames = projectAndLibs.libExportNames == undefined? [] : projectAndLibs.libExportNames;
      console.log(reservedProperties)
      assert.strictEqual(reservedProperties.includes('projectPropertyAssignment1'), true);
      assert.strictEqual(reservedProperties.includes('projectPropertyAssignment2'), true);
      assert.strictEqual(reservedProperties.includes('projectPropertyAssignment3'), true);
      assert.strictEqual(reservedProperties.includes('projectPropertyAssignment4'), true);
      assert.strictEqual(reservedProperties.includes('projectIndirectObj'), false);
      assert.strictEqual(reservedProperties.includes('indirectProp1'), true);
      assert.strictEqual(reservedProperties.includes('projectShorthand'), true);
      assert.strictEqual(reservedProperties.includes('projectShorthandProp'), true);
      assert.strictEqual(reservedProperties.includes('projectMethod1'), true);
      assert.strictEqual(reservedProperties.includes('projectMethod2'), true);
      assert.strictEqual(reservedProperties.includes('projectMethod3'), true);
      assert.strictEqual(reservedProperties.includes('projectGetProp1'), true);
      assert.strictEqual(reservedProperties.includes('projectGetProp2'), true);
      assert.strictEqual(reservedProperties.includes('projectGetProp3'), true);
      assert.strictEqual(reservedProperties.includes('projectSetProp1'), true);
      assert.strictEqual(reservedProperties.includes('projectSetProp2'), true);
      assert.strictEqual(reservedProperties.includes('projectSetProp3'), true);
      assert.strictEqual(reservedProperties.includes('projectExportElement1'), true);
      assert.strictEqual(reservedProperties.includes('projectExportElement2'), true);
      assert.strictEqual(reservedProperties.includes('indirectClass1'), false);
      assert.strictEqual(reservedProperties.includes('indirectProp2'), true);
      assert.strictEqual(reservedProperties.includes('projectExportElement3'), true);
      assert.strictEqual(reservedProperties.includes('indirectClass2'), false);
      assert.strictEqual(reservedProperties.includes('indirectProp3'), true);
      assert.strictEqual(reservedProperties.includes('projectExportElement4'), true);
      assert.strictEqual(reservedProperties.includes('indirectProp4'), true);
      assert.strictEqual(reservedProperties.includes('projectExportElement5'), true);
      assert.strictEqual(reservedProperties.includes('projectExportElement6'), true);
      assert.strictEqual(reservedProperties.includes('projectExportElement7'), true);
      assert.strictEqual(reservedProperties.includes('indirectClass3'), false);
      assert.strictEqual(reservedProperties.includes('indirectProp5'), true);
      assert.strictEqual(reservedProperties.includes('projectExportElement8'), true);
      assert.strictEqual(reservedProperties.includes('indirectClass4'), false);
      assert.strictEqual(reservedProperties.includes('indirectProp6'), true);
      assert.strictEqual(reservedProperties.includes('projectExportElement9'), true);
      assert.strictEqual(reservedProperties.includes('indirectProp7'), true);
      assert.strictEqual(reservedProperties.includes('ohPropertyAssignment1'), true);
      assert.strictEqual(reservedProperties.includes('ohPropertyAssignment2'), true);
      assert.strictEqual(reservedProperties.includes('ohPropertyAssignment3'), true);
      assert.strictEqual(reservedProperties.includes('ohPropertyAssignment4'), true);
      assert.strictEqual(reservedProperties.includes('ohIndirectObj'), false);
      assert.strictEqual(reservedProperties.includes('ohIndirectProp1'), true);
      assert.strictEqual(reservedProperties.includes('ohShorthand'), true);
      assert.strictEqual(reservedProperties.includes('ohShorthandProp'), true);
      assert.strictEqual(reservedProperties.includes('ohMethod1'), true);
      assert.strictEqual(reservedProperties.includes('ohMethod2'), true);
      assert.strictEqual(reservedProperties.includes('ohMethod3'), true);
      assert.strictEqual(reservedProperties.includes('ohGetProp1'), true);
      assert.strictEqual(reservedProperties.includes('ohGetProp2'), true);
      assert.strictEqual(reservedProperties.includes('ohGetProp3'), true);
      assert.strictEqual(reservedProperties.includes('ohSetProp1'), true);
      assert.strictEqual(reservedProperties.includes('ohSetProp2'), true);
      assert.strictEqual(reservedProperties.includes('ohSetProp3'), true);
      assert.strictEqual(reservedProperties.includes('ohExportElement1'), true);
      assert.strictEqual(reservedProperties.includes('ohExportElement2'), true);
      assert.strictEqual(reservedProperties.includes('ohIndirectClass1'), false);
      assert.strictEqual(reservedProperties.includes('ohIndirectProp2'), true);
      assert.strictEqual(reservedProperties.includes('ohExportElement3'), true);
      assert.strictEqual(reservedProperties.includes('ohIndirectClass2'), false);
      assert.strictEqual(reservedProperties.includes('ohIndirectProp3'), true);
      assert.strictEqual(reservedProperties.includes('ohExportElement4'), true);
      assert.strictEqual(reservedProperties.includes('ohIndirectProp4'), true);
      assert.strictEqual(reservedProperties.includes('ohExportElement5'), true);
      assert.strictEqual(reservedProperties.includes('ohExportElement6'), true);
      assert.strictEqual(reservedProperties.includes('ohExportElement7'), true);
      assert.strictEqual(reservedProperties.includes('ohIndirectClass3'), false);
      assert.strictEqual(reservedProperties.includes('ohIndirectProp5'), true);
      assert.strictEqual(reservedProperties.includes('ohExportElement8'), true);
      assert.strictEqual(reservedProperties.includes('ohIndirectClass4'), false);
      assert.strictEqual(reservedProperties.includes('ohIndirectProp6'), true);
      assert.strictEqual(reservedExportNames.length === 0, true);
    });

    it('test for module.exports(export)', function () {
      let projectAndLibs = readProjectPropertiesByCollectedPaths(fileList,
        {
          mNameObfuscation: {
            mEnable: true,
            mReservedProperties: [],
            mRenameProperties: false,
            mKeepStringProperty: false,
            mNameGeneratorType: NameGeneratorType.ORDERED,
            mReservedNames: [], 
            mReservedToplevelNames: []
          },
          mExportObfuscation: true,
          mKeepFileSourceCode: {
            mKeepSourceOfPaths: new Set(),
            mkeepFilesAndDependencies: new Set(["test/ut/utils/module_exports_test/exportFile3.js"]),
          }
        }, true);
      let reservedProperties = projectAndLibs.projectAndLibsReservedProperties == undefined? [] : projectAndLibs.projectAndLibsReservedProperties;
      let reservedExportNames = projectAndLibs.libExportNames == undefined? [] : projectAndLibs.libExportNames;
      assert.strictEqual(reservedExportNames.includes('projectPropertyAssignment1'), false);
      assert.strictEqual(reservedExportNames.includes('projectPropertyAssignment2'), false);
      assert.strictEqual(reservedExportNames.includes('projectPropertyAssignment3'), false);
      assert.strictEqual(reservedExportNames.includes('projectPropertyAssignment4'), false);
      assert.strictEqual(reservedExportNames.includes('projectIndirectObj'), false);
      assert.strictEqual(reservedExportNames.includes('indirectProp1'), false);
      assert.strictEqual(reservedExportNames.includes('projectShorthand'), false);
      assert.strictEqual(reservedExportNames.includes('projectShorthandProp'), false);
      assert.strictEqual(reservedExportNames.includes('projectMethod1'), false);
      assert.strictEqual(reservedExportNames.includes('projectMethod2'), false);
      assert.strictEqual(reservedExportNames.includes('projectMethod3'), false);
      assert.strictEqual(reservedExportNames.includes('projectGetProp1'), false);
      assert.strictEqual(reservedExportNames.includes('projectGetProp2'), false);
      assert.strictEqual(reservedExportNames.includes('projectGetProp3'), false);
      assert.strictEqual(reservedExportNames.includes('projectSetProp1'), false);
      assert.strictEqual(reservedExportNames.includes('projectSetProp2'), false);
      assert.strictEqual(reservedExportNames.includes('projectSetProp3'), false);
      assert.strictEqual(reservedExportNames.includes('projectExportElement1'), false);
      assert.strictEqual(reservedExportNames.includes('projectExportElement2'), false);
      assert.strictEqual(reservedExportNames.includes('indirectClass1'), false);
      assert.strictEqual(reservedExportNames.includes('indirectProp2'), false);
      assert.strictEqual(reservedExportNames.includes('projectExportElement3'), false);
      assert.strictEqual(reservedExportNames.includes('indirectClass2'), false);
      assert.strictEqual(reservedExportNames.includes('indirectProp3'), false);
      assert.strictEqual(reservedExportNames.includes('projectExportElement4'), false);
      assert.strictEqual(reservedExportNames.includes('indirectProp4'), false);
      assert.strictEqual(reservedExportNames.includes('projectExportElement5'), false);
      assert.strictEqual(reservedExportNames.includes('projectExportElement6'), false);
      assert.strictEqual(reservedExportNames.includes('projectExportElement7'), false);
      assert.strictEqual(reservedExportNames.includes('indirectClass3'), false);
      assert.strictEqual(reservedExportNames.includes('indirectProp5'), false);
      assert.strictEqual(reservedExportNames.includes('projectExportElement8'), false);
      assert.strictEqual(reservedExportNames.includes('indirectClass4'), false);
      assert.strictEqual(reservedExportNames.includes('indirectProp6'), false);
      assert.strictEqual(reservedExportNames.includes('projectExportElement9'), false);
      assert.strictEqual(reservedExportNames.includes('indirectProp7'), false);
      assert.strictEqual(reservedExportNames.includes('ohPropertyAssignment1'), true);
      assert.strictEqual(reservedExportNames.includes('ohPropertyAssignment2'), true);
      assert.strictEqual(reservedExportNames.includes('ohPropertyAssignment3'), true);
      assert.strictEqual(reservedExportNames.includes('ohPropertyAssignment4'), true);
      assert.strictEqual(reservedExportNames.includes('ohIndirectObj'), false);
      assert.strictEqual(reservedExportNames.includes('ohIndirectProp1'), false);
      assert.strictEqual(reservedExportNames.includes('ohShorthand'), true);
      assert.strictEqual(reservedExportNames.includes('ohShorthandProp'), false);
      assert.strictEqual(reservedExportNames.includes('ohMethod1'), true);
      assert.strictEqual(reservedExportNames.includes('ohMethod2'), true);
      assert.strictEqual(reservedExportNames.includes('ohMethod3'), true);
      assert.strictEqual(reservedExportNames.includes('ohGetProp1'), true);
      assert.strictEqual(reservedExportNames.includes('ohGetProp2'), true);
      assert.strictEqual(reservedExportNames.includes('ohGetProp3'), true);
      assert.strictEqual(reservedExportNames.includes('ohSetProp1'), true);
      assert.strictEqual(reservedExportNames.includes('ohSetProp2'), true);
      assert.strictEqual(reservedExportNames.includes('ohSetProp3'), true);
      assert.strictEqual(reservedExportNames.includes('ohExportElement1'), true);
      assert.strictEqual(reservedExportNames.includes('ohExportElement2'), true);
      assert.strictEqual(reservedExportNames.includes('ohIndirectClass1'), true);
      assert.strictEqual(reservedExportNames.includes('ohIndirectProp2'), false);
      assert.strictEqual(reservedExportNames.includes('ohExportElement3'), true);
      assert.strictEqual(reservedExportNames.includes('ohIndirectClass2'), false);
      assert.strictEqual(reservedExportNames.includes('ohIndirectProp3'), false);
      assert.strictEqual(reservedExportNames.includes('ohExportElement4'), true);
      assert.strictEqual(reservedExportNames.includes('ohIndirectProp4'), false);
      assert.strictEqual(reservedExportNames.includes('ohExportElement5'), true);
      assert.strictEqual(reservedExportNames.includes('ohExportElement6'), true);
      assert.strictEqual(reservedExportNames.includes('ohExportElement7'), true);
      assert.strictEqual(reservedExportNames.includes('ohIndirectClass3'), true);
      assert.strictEqual(reservedExportNames.includes('ohIndirectProp5'), false);
      assert.strictEqual(reservedExportNames.includes('ohExportElement8'), true);
      assert.strictEqual(reservedExportNames.includes('ohIndirectClass4'), false);
      assert.strictEqual(reservedExportNames.includes('ohIndirectProp6'), false);
      assert.strictEqual(reservedExportNames.includes('ohExportElement9'), true);
      assert.strictEqual(reservedExportNames.includes('ohIndirectProp7'), false);
      assert.strictEqual(reservedProperties.length === 0, true);
    });

    it('test for module.exports(property + export)', function () {
      let projectAndLibs = readProjectPropertiesByCollectedPaths(fileList,
        {
          mNameObfuscation: {
            mEnable: true,
            mReservedProperties: [],
            mRenameProperties: true,
            mKeepStringProperty: false,
            mNameGeneratorType: NameGeneratorType.ORDERED,
            mReservedNames: [], 
            mReservedToplevelNames: []
          },
          mExportObfuscation: true,
          mKeepFileSourceCode: {
            mKeepSourceOfPaths: new Set(),
            mkeepFilesAndDependencies: new Set(["test/ut/utils/module_exports_test/exportFile3.js"]),
          }
        }, true);
      let reservedProperties = projectAndLibs.projectAndLibsReservedProperties == undefined? [] : projectAndLibs.projectAndLibsReservedProperties;
      let reservedExportNames = projectAndLibs.libExportNames == undefined? [] : projectAndLibs.libExportNames;
      assert.strictEqual(reservedProperties.includes('projectPropertyAssignment1'), false);
      assert.strictEqual(reservedProperties.includes('projectPropertyAssignment2'), false);
      assert.strictEqual(reservedProperties.includes('projectPropertyAssignment3'), false);
      assert.strictEqual(reservedProperties.includes('projectPropertyAssignment4'), false);
      assert.strictEqual(reservedProperties.includes('projectIndirectObj'), false);
      assert.strictEqual(reservedProperties.includes('indirectProp1'), false);
      assert.strictEqual(reservedProperties.includes('projectShorthand'), false);
      assert.strictEqual(reservedProperties.includes('projectShorthandProp'), false);
      assert.strictEqual(reservedProperties.includes('projectMethod1'), false);
      assert.strictEqual(reservedProperties.includes('projectMethod2'), false);
      assert.strictEqual(reservedProperties.includes('projectMethod3'), false);
      assert.strictEqual(reservedProperties.includes('projectGetProp1'), false);
      assert.strictEqual(reservedProperties.includes('projectGetProp2'), false);
      assert.strictEqual(reservedProperties.includes('projectGetProp3'), false);
      assert.strictEqual(reservedProperties.includes('projectSetProp1'), false);
      assert.strictEqual(reservedProperties.includes('projectSetProp2'), false);
      assert.strictEqual(reservedProperties.includes('projectSetProp3'), false);
      assert.strictEqual(reservedProperties.includes('projectExportElement1'), false);
      assert.strictEqual(reservedProperties.includes('projectExportElement2'), false);
      assert.strictEqual(reservedProperties.includes('indirectClass1'), false);
      assert.strictEqual(reservedProperties.includes('indirectProp2'), false);
      assert.strictEqual(reservedProperties.includes('projectExportElement3'), false);
      assert.strictEqual(reservedProperties.includes('indirectClass2'), false);
      assert.strictEqual(reservedProperties.includes('indirectProp3'), false);
      assert.strictEqual(reservedProperties.includes('projectExportElement4'), false);
      assert.strictEqual(reservedProperties.includes('indirectProp4'), false);
      assert.strictEqual(reservedProperties.includes('projectExportElement5'), false);
      assert.strictEqual(reservedProperties.includes('projectExportElement6'), false);
      assert.strictEqual(reservedProperties.includes('projectExportElement7'), false);
      assert.strictEqual(reservedProperties.includes('indirectClass3'), false);
      assert.strictEqual(reservedProperties.includes('indirectProp5'), false);
      assert.strictEqual(reservedProperties.includes('projectExportElement8'), false);
      assert.strictEqual(reservedProperties.includes('indirectClass4'), false);
      assert.strictEqual(reservedProperties.includes('indirectProp6'), false);
      assert.strictEqual(reservedProperties.includes('projectExportElement9'), false);
      assert.strictEqual(reservedProperties.includes('indirectProp7'), false);
      assert.strictEqual(reservedProperties.includes('ohPropertyAssignment1'), true);
      assert.strictEqual(reservedProperties.includes('ohPropertyAssignment2'), true);
      assert.strictEqual(reservedProperties.includes('ohPropertyAssignment3'), true);
      assert.strictEqual(reservedProperties.includes('ohPropertyAssignment4'), true);
      assert.strictEqual(reservedProperties.includes('ohIndirectObj'), false);
      assert.strictEqual(reservedProperties.includes('ohIndirectProp1'), true);
      assert.strictEqual(reservedProperties.includes('ohShorthand'), true);
      assert.strictEqual(reservedProperties.includes('ohShorthandProp'), true);
      assert.strictEqual(reservedProperties.includes('ohMethod1'), true);
      assert.strictEqual(reservedProperties.includes('ohMethod2'), true);
      assert.strictEqual(reservedProperties.includes('ohMethod3'), true);
      assert.strictEqual(reservedProperties.includes('ohGetProp1'), true);
      assert.strictEqual(reservedProperties.includes('ohGetProp2'), true);
      assert.strictEqual(reservedProperties.includes('ohGetProp3'), true);
      assert.strictEqual(reservedProperties.includes('ohSetProp1'), true);
      assert.strictEqual(reservedProperties.includes('ohSetProp2'), true);
      assert.strictEqual(reservedProperties.includes('ohSetProp3'), true);
      assert.strictEqual(reservedProperties.includes('ohExportElement1'), true);
      assert.strictEqual(reservedProperties.includes('ohExportElement2'), true);
      assert.strictEqual(reservedProperties.includes('ohIndirectClass1'), false);
      assert.strictEqual(reservedProperties.includes('ohIndirectProp2'), true);
      assert.strictEqual(reservedProperties.includes('ohExportElement3'), true);
      assert.strictEqual(reservedProperties.includes('ohIndirectClass2'), false);
      assert.strictEqual(reservedProperties.includes('ohIndirectProp3'), true);
      assert.strictEqual(reservedProperties.includes('ohExportElement4'), true);
      assert.strictEqual(reservedProperties.includes('ohIndirectProp4'), true);
      assert.strictEqual(reservedProperties.includes('ohExportElement5'), true);
      assert.strictEqual(reservedProperties.includes('ohExportElement6'), true);
      assert.strictEqual(reservedProperties.includes('ohExportElement7'), true);
      assert.strictEqual(reservedProperties.includes('ohIndirectClass3'), false);
      assert.strictEqual(reservedProperties.includes('ohIndirectProp5'), true);
      assert.strictEqual(reservedProperties.includes('ohExportElement8'), true);
      assert.strictEqual(reservedProperties.includes('ohIndirectClass4'), false);
      assert.strictEqual(reservedProperties.includes('ohIndirectProp6'), true);
      assert.strictEqual(reservedExportNames.includes('projectPropertyAssignment1'), false);
      assert.strictEqual(reservedExportNames.includes('projectPropertyAssignment2'), false);
      assert.strictEqual(reservedExportNames.includes('projectPropertyAssignment3'), false);
      assert.strictEqual(reservedExportNames.includes('projectPropertyAssignment4'), false);
      assert.strictEqual(reservedExportNames.includes('projectIndirectObj'), false);
      assert.strictEqual(reservedExportNames.includes('indirectProp1'), false);
      assert.strictEqual(reservedExportNames.includes('projectShorthand'), false);
      assert.strictEqual(reservedExportNames.includes('projectShorthandProp'), false);
      assert.strictEqual(reservedExportNames.includes('projectMethod1'), false);
      assert.strictEqual(reservedExportNames.includes('projectMethod2'), false);
      assert.strictEqual(reservedExportNames.includes('projectMethod3'), false);
      assert.strictEqual(reservedExportNames.includes('projectGetProp1'), false);
      assert.strictEqual(reservedExportNames.includes('projectGetProp2'), false);
      assert.strictEqual(reservedExportNames.includes('projectGetProp3'), false);
      assert.strictEqual(reservedExportNames.includes('projectSetProp1'), false);
      assert.strictEqual(reservedExportNames.includes('projectSetProp2'), false);
      assert.strictEqual(reservedExportNames.includes('projectSetProp3'), false);
      assert.strictEqual(reservedExportNames.includes('projectExportElement1'), false);
      assert.strictEqual(reservedExportNames.includes('projectExportElement2'), false);
      assert.strictEqual(reservedExportNames.includes('indirectClass1'), false);
      assert.strictEqual(reservedExportNames.includes('indirectProp2'), false);
      assert.strictEqual(reservedExportNames.includes('projectExportElement3'), false);
      assert.strictEqual(reservedExportNames.includes('indirectClass2'), false);
      assert.strictEqual(reservedExportNames.includes('indirectProp3'), false);
      assert.strictEqual(reservedExportNames.includes('projectExportElement4'), false);
      assert.strictEqual(reservedExportNames.includes('indirectProp4'), false);
      assert.strictEqual(reservedExportNames.includes('projectExportElement5'), false);
      assert.strictEqual(reservedExportNames.includes('projectExportElement6'), false);
      assert.strictEqual(reservedExportNames.includes('projectExportElement7'), false);
      assert.strictEqual(reservedExportNames.includes('indirectClass3'), false);
      assert.strictEqual(reservedExportNames.includes('indirectProp5'), false);
      assert.strictEqual(reservedExportNames.includes('projectExportElement8'), false);
      assert.strictEqual(reservedExportNames.includes('indirectClass4'), false);
      assert.strictEqual(reservedExportNames.includes('indirectProp6'), false);
      assert.strictEqual(reservedExportNames.includes('projectExportElement9'), false);
      assert.strictEqual(reservedExportNames.includes('indirectProp7'), false);
      assert.strictEqual(reservedExportNames.includes('ohPropertyAssignment1'), true);
      assert.strictEqual(reservedExportNames.includes('ohPropertyAssignment2'), true);
      assert.strictEqual(reservedExportNames.includes('ohPropertyAssignment3'), true);
      assert.strictEqual(reservedExportNames.includes('ohPropertyAssignment4'), true);
      assert.strictEqual(reservedExportNames.includes('ohIndirectObj'), false);
      assert.strictEqual(reservedExportNames.includes('ohIndirectProp1'), false);
      assert.strictEqual(reservedExportNames.includes('ohShorthand'), true);
      assert.strictEqual(reservedExportNames.includes('ohShorthandProp'), false);
      assert.strictEqual(reservedExportNames.includes('ohMethod1'), true);
      assert.strictEqual(reservedExportNames.includes('ohMethod2'), true);
      assert.strictEqual(reservedExportNames.includes('ohMethod3'), true);
      assert.strictEqual(reservedExportNames.includes('ohGetProp1'), true);
      assert.strictEqual(reservedExportNames.includes('ohGetProp2'), true);
      assert.strictEqual(reservedExportNames.includes('ohGetProp3'), true);
      assert.strictEqual(reservedExportNames.includes('ohSetProp1'), true);
      assert.strictEqual(reservedExportNames.includes('ohSetProp2'), true);
      assert.strictEqual(reservedExportNames.includes('ohSetProp3'), true);
      assert.strictEqual(reservedExportNames.includes('ohExportElement1'), true);
      assert.strictEqual(reservedExportNames.includes('ohExportElement2'), true);
      assert.strictEqual(reservedExportNames.includes('ohIndirectClass1'), true);
      assert.strictEqual(reservedExportNames.includes('ohIndirectProp2'), false);
      assert.strictEqual(reservedExportNames.includes('ohExportElement3'), true);
      assert.strictEqual(reservedExportNames.includes('ohIndirectClass2'), false);
      assert.strictEqual(reservedExportNames.includes('ohIndirectProp3'), false);
      assert.strictEqual(reservedExportNames.includes('ohExportElement4'), true);
      assert.strictEqual(reservedExportNames.includes('ohIndirectProp4'), false);
      assert.strictEqual(reservedExportNames.includes('ohExportElement5'), true);
      assert.strictEqual(reservedExportNames.includes('ohExportElement6'), true);
      assert.strictEqual(reservedExportNames.includes('ohExportElement7'), true);
      assert.strictEqual(reservedExportNames.includes('ohIndirectClass3'), true);
      assert.strictEqual(reservedExportNames.includes('ohIndirectProp5'), false);
      assert.strictEqual(reservedExportNames.includes('ohExportElement8'), true);
      assert.strictEqual(reservedExportNames.includes('ohIndirectClass4'), false);
      assert.strictEqual(reservedExportNames.includes('ohIndirectProp6'), false);
      assert.strictEqual(reservedExportNames.includes('ohExportElement9'), true);
      assert.strictEqual(reservedExportNames.includes('ohIndirectProp7'), false);
    });
  });
});