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
});