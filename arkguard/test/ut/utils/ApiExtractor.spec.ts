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
import {assert, expect} from 'chai';
import { readProjectPropertiesByCollectedPaths } from '../../../src/common/ApiReader';
import { NameGeneratorType } from '../../../src/generator/NameFactory';

function collectApi(apiPath: string, apiType: ApiExtractor.ApiType): void {
  clearAll();
  ApiExtractor.traverseApiFiles(apiPath, apiType);
}

function clearAll(): void {
  ApiExtractor.mPropertySet.clear();
  ApiExtractor.mSystemExportSet.clear();
}

describe('test for ApiExtractor', function () {
  describe('test for visitExport', function () {
    it('export {ExportDeclarationClass1, ExportDeclarationClass2}', function () {
      let exportDeclarationAst: string = 'test/ut/utils/apiTest_visitExport/exportDeclarationAst.d.ts';
      collectApi(exportDeclarationAst, ApiExtractor.ApiType.API);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('ExportDeclarationClass1'), true);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('ExportDeclarationClass2'), true);
      clearAll();
    });

    it('export {ExportDeclarationClass1 as class1, ExportDeclarationClass2} from `./exportDeclarationFrom`',
     function () {
      let exportDeclarationFromAst: string = 'test/ut/utils/apiTest_visitExport/exportDeclarationFrom.d.ts';
      collectApi(exportDeclarationFromAst, ApiExtractor.ApiType.API);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('ExportDeclarationClass1'), false);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('class1'), true);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('ExportDeclarationClass2'), true);
      clearAll();
    });

    it('export {default as name1, ExportDeclarationClass2, exportName} from `./exportDefaultDeclarationAst`',
     function () {
      let exportDeclarationDefault: string = 'test/ut/utils/apiTest_visitExport/exportDeclarationDefault.d.ts';
      collectApi(exportDeclarationDefault, ApiExtractor.ApiType.API);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('default'), false);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('name1'), true);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('ExportDeclarationClass2'), true);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('exportName'), true);
      clearAll();
    });

    it('export {ExportDeclarationClass1 as exportName, ExportDeclarationClass2, ExportDeclarationClass3 as default}',
     function () {
      let exportDefaultDeclarationAst: string = 'test/ut/utils/apiTest_visitExport/exportDefaultDeclarationAst.d.ts';
      collectApi(exportDefaultDeclarationAst, ApiExtractor.ApiType.API);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('ExportDeclarationClass1'), false);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('exportName'), true);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('ExportDeclarationClass2'), true);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('ExportDeclarationClass3'), false);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('default'), true);
      clearAll();
    });

    it('export * as name1', function () {
      let exportAllAst: string = 'test/ut/utils/apiTest_visitExport/exportAll.d.ts';
      collectApi(exportAllAst, ApiExtractor.ApiType.API);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('name1'), true);
      clearAll();
    });

    it('export * from `export*.ts`', function () {
      let exportFile: string = 'test/ut/utils/apiTest_visitExport/export.d.ts';
      collectApi(exportFile, ApiExtractor.ApiType.API);
      assert.strictEqual(ApiExtractor.mSystemExportSet.size === 0, true);
      assert.strictEqual(ApiExtractor.mPropertySet.size === 0, true);
      clearAll();
    });

    it('doubleUnderscoreTest', function () {
      let doubleUnderscoreTestAst: string = 'test/ut/utils/apiTest_visitExport/doubleUnderscoreTest.d.ts';
      collectApi(doubleUnderscoreTestAst, ApiExtractor.ApiType.API);
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
      collectApi(filePath, ApiExtractor.ApiType.API);
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
      collectApi(filePath, ApiExtractor.ApiType.API);
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
      collectApi(filePath, ApiExtractor.ApiType.API);
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
      collectApi(filePath, ApiExtractor.ApiType.API);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('TestEnum1'), true);
      assert.strictEqual(ApiExtractor.mSystemExportSet.has('TestEnum2'), false);
      assert.strictEqual(ApiExtractor.mPropertySet.has('PARAM1'), true);
      assert.strictEqual(ApiExtractor.mPropertySet.has('PARAM2'), true);
      clearAll();
    });

    it('ObjectLiteral Test', function () {
      let filePath: string = 'test/ut/utils/apiTest_visitPropertyAndName/objectLiteral.d.ts';
      collectApi(filePath, ApiExtractor.ApiType.API);
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
      collectApi(filePath, ApiExtractor.ApiType.API);
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
      let reservedProperties = projectAndLibs.exportNameAndPropSet == undefined? new Set<string> : projectAndLibs.exportNameAndPropSet;
      let reservedExportNames = projectAndLibs.exportNameSet == undefined? new Set<string> : projectAndLibs.exportNameSet;
      assert.strictEqual(reservedProperties.has('projectPropertyAssignment1'), true);
      assert.strictEqual(reservedProperties.has('projectPropertyAssignment2'), true);
      assert.strictEqual(reservedProperties.has('projectPropertyAssignment3'), true);
      assert.strictEqual(reservedProperties.has('projectPropertyAssignment4'), true);
      assert.strictEqual(reservedProperties.has('projectIndirectObj'), false);
      assert.strictEqual(reservedProperties.has('indirectProp1'), true);
      assert.strictEqual(reservedProperties.has('projectShorthand'), true);
      assert.strictEqual(reservedProperties.has('projectShorthandProp'), true);
      assert.strictEqual(reservedProperties.has('projectMethod1'), true);
      assert.strictEqual(reservedProperties.has('projectMethod2'), true);
      assert.strictEqual(reservedProperties.has('projectMethod3'), true);
      assert.strictEqual(reservedProperties.has('projectGetProp1'), true);
      assert.strictEqual(reservedProperties.has('projectGetProp2'), true);
      assert.strictEqual(reservedProperties.has('projectGetProp3'), true);
      assert.strictEqual(reservedProperties.has('projectSetProp1'), true);
      assert.strictEqual(reservedProperties.has('projectSetProp2'), true);
      assert.strictEqual(reservedProperties.has('projectSetProp3'), true);
      assert.strictEqual(reservedProperties.has('projectExportElement1'), true);
      assert.strictEqual(reservedProperties.has('projectExportElement2'), true);
      assert.strictEqual(reservedProperties.has('indirectClass1'), false);
      assert.strictEqual(reservedProperties.has('indirectProp2'), true);
      assert.strictEqual(reservedProperties.has('projectExportElement3'), true);
      assert.strictEqual(reservedProperties.has('indirectClass2'), false);
      assert.strictEqual(reservedProperties.has('indirectProp3'), true);
      assert.strictEqual(reservedProperties.has('projectExportElement4'), true);
      assert.strictEqual(reservedProperties.has('indirectProp4'), true);
      assert.strictEqual(reservedProperties.has('projectExportElement5'), true);
      assert.strictEqual(reservedProperties.has('projectExportElement6'), true);
      assert.strictEqual(reservedProperties.has('projectExportElement7'), true);
      assert.strictEqual(reservedProperties.has('indirectClass3'), false);
      assert.strictEqual(reservedProperties.has('indirectProp5'), true);
      assert.strictEqual(reservedProperties.has('projectExportElement8'), true);
      assert.strictEqual(reservedProperties.has('indirectClass4'), false);
      assert.strictEqual(reservedProperties.has('indirectProp6'), true);
      assert.strictEqual(reservedProperties.has('projectExportElement9'), true);
      assert.strictEqual(reservedProperties.has('indirectProp7'), true);
      assert.strictEqual(reservedProperties.has('ohPropertyAssignment1'), true);
      assert.strictEqual(reservedProperties.has('ohPropertyAssignment2'), true);
      assert.strictEqual(reservedProperties.has('ohPropertyAssignment3'), true);
      assert.strictEqual(reservedProperties.has('ohPropertyAssignment4'), true);
      assert.strictEqual(reservedProperties.has('ohIndirectObj'), false);
      assert.strictEqual(reservedProperties.has('ohIndirectProp1'), true);
      assert.strictEqual(reservedProperties.has('ohShorthand'), true);
      assert.strictEqual(reservedProperties.has('ohShorthandProp'), true);
      assert.strictEqual(reservedProperties.has('ohMethod1'), true);
      assert.strictEqual(reservedProperties.has('ohMethod2'), true);
      assert.strictEqual(reservedProperties.has('ohMethod3'), true);
      assert.strictEqual(reservedProperties.has('ohGetProp1'), true);
      assert.strictEqual(reservedProperties.has('ohGetProp2'), true);
      assert.strictEqual(reservedProperties.has('ohGetProp3'), true);
      assert.strictEqual(reservedProperties.has('ohSetProp1'), true);
      assert.strictEqual(reservedProperties.has('ohSetProp2'), true);
      assert.strictEqual(reservedProperties.has('ohSetProp3'), true);
      assert.strictEqual(reservedProperties.has('ohExportElement1'), true);
      assert.strictEqual(reservedProperties.has('ohExportElement2'), true);
      assert.strictEqual(reservedProperties.has('ohIndirectClass1'), false);
      assert.strictEqual(reservedProperties.has('ohIndirectProp2'), true);
      assert.strictEqual(reservedProperties.has('ohExportElement3'), true);
      assert.strictEqual(reservedProperties.has('ohIndirectClass2'), false);
      assert.strictEqual(reservedProperties.has('ohIndirectProp3'), true);
      assert.strictEqual(reservedProperties.has('ohExportElement4'), true);
      assert.strictEqual(reservedProperties.has('ohIndirectProp4'), true);
      assert.strictEqual(reservedProperties.has('ohExportElement5'), true);
      assert.strictEqual(reservedProperties.has('ohExportElement6'), true);
      assert.strictEqual(reservedProperties.has('ohExportElement7'), true);
      assert.strictEqual(reservedProperties.has('ohIndirectClass3'), false);
      assert.strictEqual(reservedProperties.has('ohIndirectProp5'), true);
      assert.strictEqual(reservedProperties.has('ohExportElement8'), true);
      assert.strictEqual(reservedProperties.has('ohIndirectClass4'), false);
      assert.strictEqual(reservedProperties.has('ohIndirectProp6'), true);
      assert.strictEqual(reservedExportNames.size === 0, true);
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
      let reservedProperties = projectAndLibs.exportNameAndPropSet == undefined? new Set<string> : projectAndLibs.exportNameAndPropSet;
      let reservedExportNames = projectAndLibs.exportNameSet == undefined? new Set<string> : projectAndLibs.exportNameSet;
      assert.strictEqual(reservedExportNames.has('projectPropertyAssignment1'), false);
      assert.strictEqual(reservedExportNames.has('projectPropertyAssignment2'), false);
      assert.strictEqual(reservedExportNames.has('projectPropertyAssignment3'), false);
      assert.strictEqual(reservedExportNames.has('projectPropertyAssignment4'), false);
      assert.strictEqual(reservedExportNames.has('projectIndirectObj'), false);
      assert.strictEqual(reservedExportNames.has('indirectProp1'), false);
      assert.strictEqual(reservedExportNames.has('projectShorthand'), false);
      assert.strictEqual(reservedExportNames.has('projectShorthandProp'), false);
      assert.strictEqual(reservedExportNames.has('projectMethod1'), false);
      assert.strictEqual(reservedExportNames.has('projectMethod2'), false);
      assert.strictEqual(reservedExportNames.has('projectMethod3'), false);
      assert.strictEqual(reservedExportNames.has('projectGetProp1'), false);
      assert.strictEqual(reservedExportNames.has('projectGetProp2'), false);
      assert.strictEqual(reservedExportNames.has('projectGetProp3'), false);
      assert.strictEqual(reservedExportNames.has('projectSetProp1'), false);
      assert.strictEqual(reservedExportNames.has('projectSetProp2'), false);
      assert.strictEqual(reservedExportNames.has('projectSetProp3'), false);
      assert.strictEqual(reservedExportNames.has('projectExportElement1'), false);
      assert.strictEqual(reservedExportNames.has('projectExportElement2'), false);
      assert.strictEqual(reservedExportNames.has('indirectClass1'), false);
      assert.strictEqual(reservedExportNames.has('indirectProp2'), false);
      assert.strictEqual(reservedExportNames.has('projectExportElement3'), false);
      assert.strictEqual(reservedExportNames.has('indirectClass2'), false);
      assert.strictEqual(reservedExportNames.has('indirectProp3'), false);
      assert.strictEqual(reservedExportNames.has('projectExportElement4'), false);
      assert.strictEqual(reservedExportNames.has('indirectProp4'), false);
      assert.strictEqual(reservedExportNames.has('projectExportElement5'), false);
      assert.strictEqual(reservedExportNames.has('projectExportElement6'), false);
      assert.strictEqual(reservedExportNames.has('projectExportElement7'), false);
      assert.strictEqual(reservedExportNames.has('indirectClass3'), false);
      assert.strictEqual(reservedExportNames.has('indirectProp5'), false);
      assert.strictEqual(reservedExportNames.has('projectExportElement8'), false);
      assert.strictEqual(reservedExportNames.has('indirectClass4'), false);
      assert.strictEqual(reservedExportNames.has('indirectProp6'), false);
      assert.strictEqual(reservedExportNames.has('projectExportElement9'), false);
      assert.strictEqual(reservedExportNames.has('indirectProp7'), false);
      assert.strictEqual(reservedExportNames.has('ohPropertyAssignment1'), true);
      assert.strictEqual(reservedExportNames.has('ohPropertyAssignment2'), true);
      assert.strictEqual(reservedExportNames.has('ohPropertyAssignment3'), true);
      assert.strictEqual(reservedExportNames.has('ohPropertyAssignment4'), true);
      assert.strictEqual(reservedExportNames.has('ohIndirectObj'), false);
      assert.strictEqual(reservedExportNames.has('ohIndirectProp1'), false);
      assert.strictEqual(reservedExportNames.has('ohShorthand'), true);
      assert.strictEqual(reservedExportNames.has('ohShorthandProp'), false);
      assert.strictEqual(reservedExportNames.has('ohMethod1'), true);
      assert.strictEqual(reservedExportNames.has('ohMethod2'), true);
      assert.strictEqual(reservedExportNames.has('ohMethod3'), true);
      assert.strictEqual(reservedExportNames.has('ohGetProp1'), true);
      assert.strictEqual(reservedExportNames.has('ohGetProp2'), true);
      assert.strictEqual(reservedExportNames.has('ohGetProp3'), true);
      assert.strictEqual(reservedExportNames.has('ohSetProp1'), true);
      assert.strictEqual(reservedExportNames.has('ohSetProp2'), true);
      assert.strictEqual(reservedExportNames.has('ohSetProp3'), true);
      assert.strictEqual(reservedExportNames.has('ohExportElement1'), true);
      assert.strictEqual(reservedExportNames.has('ohExportElement2'), true);
      assert.strictEqual(reservedExportNames.has('ohIndirectClass1'), true);
      assert.strictEqual(reservedExportNames.has('ohIndirectProp2'), false);
      assert.strictEqual(reservedExportNames.has('ohExportElement3'), true);
      assert.strictEqual(reservedExportNames.has('ohIndirectClass2'), false);
      assert.strictEqual(reservedExportNames.has('ohIndirectProp3'), false);
      assert.strictEqual(reservedExportNames.has('ohExportElement4'), true);
      assert.strictEqual(reservedExportNames.has('ohIndirectProp4'), false);
      assert.strictEqual(reservedExportNames.has('ohExportElement5'), true);
      assert.strictEqual(reservedExportNames.has('ohExportElement6'), true);
      assert.strictEqual(reservedExportNames.has('ohExportElement7'), true);
      assert.strictEqual(reservedExportNames.has('ohIndirectClass3'), true);
      assert.strictEqual(reservedExportNames.has('ohIndirectProp5'), false);
      assert.strictEqual(reservedExportNames.has('ohExportElement8'), true);
      assert.strictEqual(reservedExportNames.has('ohIndirectClass4'), false);
      assert.strictEqual(reservedExportNames.has('ohIndirectProp6'), false);
      assert.strictEqual(reservedExportNames.has('ohExportElement9'), true);
      assert.strictEqual(reservedExportNames.has('ohIndirectProp7'), false);
      assert.strictEqual(reservedProperties.size === 0, true);
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
      let reservedProperties = projectAndLibs.exportNameAndPropSet == undefined? new Set<string> : projectAndLibs.exportNameAndPropSet;
      let reservedExportNames = projectAndLibs.exportNameSet == undefined? new Set<string> : projectAndLibs.exportNameSet;
      assert.strictEqual(reservedProperties.has('projectPropertyAssignment1'), false);
      assert.strictEqual(reservedProperties.has('projectPropertyAssignment2'), false);
      assert.strictEqual(reservedProperties.has('projectPropertyAssignment3'), false);
      assert.strictEqual(reservedProperties.has('projectPropertyAssignment4'), false);
      assert.strictEqual(reservedProperties.has('projectIndirectObj'), false);
      assert.strictEqual(reservedProperties.has('indirectProp1'), false);
      assert.strictEqual(reservedProperties.has('projectShorthand'), false);
      assert.strictEqual(reservedProperties.has('projectShorthandProp'), false);
      assert.strictEqual(reservedProperties.has('projectMethod1'), false);
      assert.strictEqual(reservedProperties.has('projectMethod2'), false);
      assert.strictEqual(reservedProperties.has('projectMethod3'), false);
      assert.strictEqual(reservedProperties.has('projectGetProp1'), false);
      assert.strictEqual(reservedProperties.has('projectGetProp2'), false);
      assert.strictEqual(reservedProperties.has('projectGetProp3'), false);
      assert.strictEqual(reservedProperties.has('projectSetProp1'), false);
      assert.strictEqual(reservedProperties.has('projectSetProp2'), false);
      assert.strictEqual(reservedProperties.has('projectSetProp3'), false);
      assert.strictEqual(reservedProperties.has('projectExportElement1'), false);
      assert.strictEqual(reservedProperties.has('projectExportElement2'), false);
      assert.strictEqual(reservedProperties.has('indirectClass1'), false);
      assert.strictEqual(reservedProperties.has('indirectProp2'), false);
      assert.strictEqual(reservedProperties.has('projectExportElement3'), false);
      assert.strictEqual(reservedProperties.has('indirectClass2'), false);
      assert.strictEqual(reservedProperties.has('indirectProp3'), false);
      assert.strictEqual(reservedProperties.has('projectExportElement4'), false);
      assert.strictEqual(reservedProperties.has('indirectProp4'), false);
      assert.strictEqual(reservedProperties.has('projectExportElement5'), false);
      assert.strictEqual(reservedProperties.has('projectExportElement6'), false);
      assert.strictEqual(reservedProperties.has('projectExportElement7'), false);
      assert.strictEqual(reservedProperties.has('indirectClass3'), false);
      assert.strictEqual(reservedProperties.has('indirectProp5'), false);
      assert.strictEqual(reservedProperties.has('projectExportElement8'), false);
      assert.strictEqual(reservedProperties.has('indirectClass4'), false);
      assert.strictEqual(reservedProperties.has('indirectProp6'), false);
      assert.strictEqual(reservedProperties.has('projectExportElement9'), false);
      assert.strictEqual(reservedProperties.has('indirectProp7'), false);
      assert.strictEqual(reservedProperties.has('ohPropertyAssignment1'), true);
      assert.strictEqual(reservedProperties.has('ohPropertyAssignment2'), true);
      assert.strictEqual(reservedProperties.has('ohPropertyAssignment3'), true);
      assert.strictEqual(reservedProperties.has('ohPropertyAssignment4'), true);
      assert.strictEqual(reservedProperties.has('ohIndirectObj'), false);
      assert.strictEqual(reservedProperties.has('ohIndirectProp1'), true);
      assert.strictEqual(reservedProperties.has('ohShorthand'), true);
      assert.strictEqual(reservedProperties.has('ohShorthandProp'), true);
      assert.strictEqual(reservedProperties.has('ohMethod1'), true);
      assert.strictEqual(reservedProperties.has('ohMethod2'), true);
      assert.strictEqual(reservedProperties.has('ohMethod3'), true);
      assert.strictEqual(reservedProperties.has('ohGetProp1'), true);
      assert.strictEqual(reservedProperties.has('ohGetProp2'), true);
      assert.strictEqual(reservedProperties.has('ohGetProp3'), true);
      assert.strictEqual(reservedProperties.has('ohSetProp1'), true);
      assert.strictEqual(reservedProperties.has('ohSetProp2'), true);
      assert.strictEqual(reservedProperties.has('ohSetProp3'), true);
      assert.strictEqual(reservedProperties.has('ohExportElement1'), true);
      assert.strictEqual(reservedProperties.has('ohExportElement2'), true);
      assert.strictEqual(reservedProperties.has('ohIndirectClass1'), false);
      assert.strictEqual(reservedProperties.has('ohIndirectProp2'), true);
      assert.strictEqual(reservedProperties.has('ohExportElement3'), true);
      assert.strictEqual(reservedProperties.has('ohIndirectClass2'), false);
      assert.strictEqual(reservedProperties.has('ohIndirectProp3'), true);
      assert.strictEqual(reservedProperties.has('ohExportElement4'), true);
      assert.strictEqual(reservedProperties.has('ohIndirectProp4'), true);
      assert.strictEqual(reservedProperties.has('ohExportElement5'), true);
      assert.strictEqual(reservedProperties.has('ohExportElement6'), true);
      assert.strictEqual(reservedProperties.has('ohExportElement7'), true);
      assert.strictEqual(reservedProperties.has('ohIndirectClass3'), false);
      assert.strictEqual(reservedProperties.has('ohIndirectProp5'), true);
      assert.strictEqual(reservedProperties.has('ohExportElement8'), true);
      assert.strictEqual(reservedProperties.has('ohIndirectClass4'), false);
      assert.strictEqual(reservedProperties.has('ohIndirectProp6'), true);
      assert.strictEqual(reservedExportNames.has('projectPropertyAssignment1'), false);
      assert.strictEqual(reservedExportNames.has('projectPropertyAssignment2'), false);
      assert.strictEqual(reservedExportNames.has('projectPropertyAssignment3'), false);
      assert.strictEqual(reservedExportNames.has('projectPropertyAssignment4'), false);
      assert.strictEqual(reservedExportNames.has('projectIndirectObj'), false);
      assert.strictEqual(reservedExportNames.has('indirectProp1'), false);
      assert.strictEqual(reservedExportNames.has('projectShorthand'), false);
      assert.strictEqual(reservedExportNames.has('projectShorthandProp'), false);
      assert.strictEqual(reservedExportNames.has('projectMethod1'), false);
      assert.strictEqual(reservedExportNames.has('projectMethod2'), false);
      assert.strictEqual(reservedExportNames.has('projectMethod3'), false);
      assert.strictEqual(reservedExportNames.has('projectGetProp1'), false);
      assert.strictEqual(reservedExportNames.has('projectGetProp2'), false);
      assert.strictEqual(reservedExportNames.has('projectGetProp3'), false);
      assert.strictEqual(reservedExportNames.has('projectSetProp1'), false);
      assert.strictEqual(reservedExportNames.has('projectSetProp2'), false);
      assert.strictEqual(reservedExportNames.has('projectSetProp3'), false);
      assert.strictEqual(reservedExportNames.has('projectExportElement1'), false);
      assert.strictEqual(reservedExportNames.has('projectExportElement2'), false);
      assert.strictEqual(reservedExportNames.has('indirectClass1'), false);
      assert.strictEqual(reservedExportNames.has('indirectProp2'), false);
      assert.strictEqual(reservedExportNames.has('projectExportElement3'), false);
      assert.strictEqual(reservedExportNames.has('indirectClass2'), false);
      assert.strictEqual(reservedExportNames.has('indirectProp3'), false);
      assert.strictEqual(reservedExportNames.has('projectExportElement4'), false);
      assert.strictEqual(reservedExportNames.has('indirectProp4'), false);
      assert.strictEqual(reservedExportNames.has('projectExportElement5'), false);
      assert.strictEqual(reservedExportNames.has('projectExportElement6'), false);
      assert.strictEqual(reservedExportNames.has('projectExportElement7'), false);
      assert.strictEqual(reservedExportNames.has('indirectClass3'), false);
      assert.strictEqual(reservedExportNames.has('indirectProp5'), false);
      assert.strictEqual(reservedExportNames.has('projectExportElement8'), false);
      assert.strictEqual(reservedExportNames.has('indirectClass4'), false);
      assert.strictEqual(reservedExportNames.has('indirectProp6'), false);
      assert.strictEqual(reservedExportNames.has('projectExportElement9'), false);
      assert.strictEqual(reservedExportNames.has('indirectProp7'), false);
      assert.strictEqual(reservedExportNames.has('ohPropertyAssignment1'), true);
      assert.strictEqual(reservedExportNames.has('ohPropertyAssignment2'), true);
      assert.strictEqual(reservedExportNames.has('ohPropertyAssignment3'), true);
      assert.strictEqual(reservedExportNames.has('ohPropertyAssignment4'), true);
      assert.strictEqual(reservedExportNames.has('ohIndirectObj'), false);
      assert.strictEqual(reservedExportNames.has('ohIndirectProp1'), false);
      assert.strictEqual(reservedExportNames.has('ohShorthand'), true);
      assert.strictEqual(reservedExportNames.has('ohShorthandProp'), false);
      assert.strictEqual(reservedExportNames.has('ohMethod1'), true);
      assert.strictEqual(reservedExportNames.has('ohMethod2'), true);
      assert.strictEqual(reservedExportNames.has('ohMethod3'), true);
      assert.strictEqual(reservedExportNames.has('ohGetProp1'), true);
      assert.strictEqual(reservedExportNames.has('ohGetProp2'), true);
      assert.strictEqual(reservedExportNames.has('ohGetProp3'), true);
      assert.strictEqual(reservedExportNames.has('ohSetProp1'), true);
      assert.strictEqual(reservedExportNames.has('ohSetProp2'), true);
      assert.strictEqual(reservedExportNames.has('ohSetProp3'), true);
      assert.strictEqual(reservedExportNames.has('ohExportElement1'), true);
      assert.strictEqual(reservedExportNames.has('ohExportElement2'), true);
      assert.strictEqual(reservedExportNames.has('ohIndirectClass1'), true);
      assert.strictEqual(reservedExportNames.has('ohIndirectProp2'), false);
      assert.strictEqual(reservedExportNames.has('ohExportElement3'), true);
      assert.strictEqual(reservedExportNames.has('ohIndirectClass2'), false);
      assert.strictEqual(reservedExportNames.has('ohIndirectProp3'), false);
      assert.strictEqual(reservedExportNames.has('ohExportElement4'), true);
      assert.strictEqual(reservedExportNames.has('ohIndirectProp4'), false);
      assert.strictEqual(reservedExportNames.has('ohExportElement5'), true);
      assert.strictEqual(reservedExportNames.has('ohExportElement6'), true);
      assert.strictEqual(reservedExportNames.has('ohExportElement7'), true);
      assert.strictEqual(reservedExportNames.has('ohIndirectClass3'), true);
      assert.strictEqual(reservedExportNames.has('ohIndirectProp5'), false);
      assert.strictEqual(reservedExportNames.has('ohExportElement8'), true);
      assert.strictEqual(reservedExportNames.has('ohIndirectClass4'), false);
      assert.strictEqual(reservedExportNames.has('ohIndirectProp6'), false);
      assert.strictEqual(reservedExportNames.has('ohExportElement9'), true);
      assert.strictEqual(reservedExportNames.has('ohIndirectProp7'), false);
    });
  });

  describe('test for visitNodeForConstructorProperty', function () {
    it('should collect constructor properties', function () {
      ApiExtractor.mConstructorPropertySet = new Set();
      let constructorPropertyAst: string = 'test/ut/utils/apiTest_visitConstructorProperty/constructorProperty.ts';
      collectApi(constructorPropertyAst, ApiExtractor.ApiType.CONSTRUCTOR_PROPERTY);
      expect(ApiExtractor.mConstructorPropertySet.has('para1')).to.be.true;
      expect(ApiExtractor.mConstructorPropertySet.has('para2')).to.be.true;
      expect(ApiExtractor.mConstructorPropertySet.has('para3')).to.be.true;
      expect(ApiExtractor.mConstructorPropertySet.has('para4')).to.be.true;
      clearAll();
      ApiExtractor.mConstructorPropertySet.clear();
    })
  })

  describe('test for visitEnumMembers', function () {
    it('should collect enum members', function () {
      let enumMembersAst: string = 'test/ut/utils/apiTest_visitEnumMembers/enumMembers.ts';
      collectApi(enumMembersAst, ApiExtractor.ApiType.PROJECT);
      expect(ApiExtractor.mEnumMemberSet.has('A1')).to.be.false;
      expect(ApiExtractor.mEnumMemberSet.has('A2')).to.be.false;
      expect(ApiExtractor.mEnumMemberSet.has('A3')).to.be.false;
      expect(ApiExtractor.mEnumMemberSet.has('B1')).to.be.true;
      expect(ApiExtractor.mEnumMemberSet.has('B2')).to.be.true;
      expect(ApiExtractor.mEnumMemberSet.has('B3')).to.be.true;
      expect(ApiExtractor.mEnumMemberSet.has('C1')).to.be.true;
      expect(ApiExtractor.mEnumMemberSet.has('C2')).to.be.true;
      expect(ApiExtractor.mEnumMemberSet.has('C3')).to.be.true;
      clearAll();
      ApiExtractor.mEnumMemberSet.clear();
    })
    it('should not collect enum members of js file', function () {
      let enumMembersAst: string = 'test/ut/utils/apiTest_visitEnumMembers/enumMembers.js';
      collectApi(enumMembersAst, ApiExtractor.ApiType.PROJECT);
      expect(ApiExtractor.mEnumMemberSet.size === 0).to.be.true;
    })
  })
});