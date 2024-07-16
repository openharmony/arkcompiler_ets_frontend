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

import { readProjectPropertiesByCollectedPaths, ReseverdSetForArkguard } from '../../../src/common/ApiReader';
import { assert } from 'chai';
import { NameGeneratorType } from '../../../src/generator/NameFactory';

describe('test for ApiReader', function () {
  describe('test for readProjectPropertiesByCollectedPaths', function () {
    const fileList: Set<string> = new Set([
      "test/ut/utils/apiTest_readProjectPropertiesByCollectedPaths/block_enum_test.ts",
      "test/ut/utils/apiTest_readProjectPropertiesByCollectedPaths/enum_test.ts",
      "test/ut/utils/apiTest_readProjectPropertiesByCollectedPaths/export_enum_test.ts",
      "test/ut/utils/apiTest_readProjectPropertiesByCollectedPaths/namespace_enum_test.ts"
    ]);

    it('-enable-export-obfuscation + -enable-property-obfuscation', function () {
      let projectAndLibs: ReseverdSetForArkguard =
        readProjectPropertiesByCollectedPaths(fileList,
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
            mkeepFilesAndDependencies: new Set(),
          },
          
        }, true);
      let enumPropertySet = projectAndLibs.enumPropertySet;
      assert.strictEqual(enumPropertySet.has('BLOCK_PARAM1'), true);
      assert.strictEqual(enumPropertySet.has('BLOCK_PARAM2'), true);
      assert.strictEqual(enumPropertySet.has('ENUM_PARAM1'), true);
      assert.strictEqual(enumPropertySet.has('ENUM_PARAM2'), true);
      assert.strictEqual(enumPropertySet.has('NS_PARAM1'), true);
      assert.strictEqual(enumPropertySet.has('NS_PARAM2'), true);
      assert.strictEqual(enumPropertySet.has('EXPORT_PARAM1'), true);
      assert.strictEqual(enumPropertySet.has('EXPORT_PARAM2'), true);
    });

    it('-enable-property-obfuscation', function () {
      let projectAndLibs: ReseverdSetForArkguard =
        readProjectPropertiesByCollectedPaths(fileList,
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
      let enumPropertySet = projectAndLibs.enumPropertySet;
      let exportNameAndPropSet = projectAndLibs.exportNameAndPropSet;
      assert.strictEqual(enumPropertySet.has('BLOCK_PARAM1'), true);
      assert.strictEqual(enumPropertySet.has('BLOCK_PARAM2'), true);
      assert.strictEqual(enumPropertySet.has('ENUM_PARAM1'), true);
      assert.strictEqual(enumPropertySet.has('ENUM_PARAM2'), true);
      assert.strictEqual(enumPropertySet.has('NS_PARAM1'), true);
      assert.strictEqual(enumPropertySet.has('NS_PARAM2'), true);
      assert.strictEqual(enumPropertySet.has('EXPORT_PARAM1'), true);
      assert.strictEqual(enumPropertySet.has('EXPORT_PARAM2'), true);
      assert.strictEqual(exportNameAndPropSet.has('ExportEnum'), true);
      assert.strictEqual(exportNameAndPropSet.has('EXPORT_PARAM1'), true);
      assert.strictEqual(exportNameAndPropSet.has('EXPORT_PARAM2'), true);
    });

    it('-enable-export-obfuscation', function () {
      let projectAndLibs: ReseverdSetForArkguard =
        readProjectPropertiesByCollectedPaths(fileList,
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
            mkeepFilesAndDependencies: new Set(),
          }
        }, true);
      let exportNameAndPropSet = projectAndLibs.exportNameAndPropSet;
      let exportNameSet = projectAndLibs.exportNameSet;
      assert.strictEqual(exportNameAndPropSet, undefined);
      assert.strictEqual(exportNameSet.has('ExportEnum'), false);
    });
  });

  describe('test for -keep and export obfuscation', function () {
    const fileList: Set<string> = new Set([
      "test/ut/utils/keep_export/exportFile1.ts"
    ]);

    it('-enable-export-obfuscation', function () {
      let projectAndLibs: ReseverdSetForArkguard =
        readProjectPropertiesByCollectedPaths(fileList,
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
            mkeepFilesAndDependencies: new Set([
              "test/ut/utils/keep_export/exportFile1.ts"
            ]),
          }
        }, true);
      let exportNameSet = projectAndLibs.exportNameSet;
      let exportNameAndPropSet = projectAndLibs.exportNameAndPropSet;
      assert.strictEqual(exportNameSet.has('TestClass'), true);
      assert.strictEqual(exportNameSet.has('prop1'), false);
      assert.strictEqual(exportNameSet.has('prop2'), false);
      assert.strictEqual(exportNameSet.has('objProp'), false);
      assert.strictEqual(exportNameSet.has('innerProp2'), false);
      assert.strictEqual(exportNameSet.has('var1'), true);
      assert.strictEqual(exportNameSet.has('var2'), false);
      assert.strictEqual(exportNameSet.has('foo'), true);
      assert.strictEqual(exportNameSet.has('ns'), false);
      assert.strictEqual(exportNameSet.has('var3'), true);
      assert.strictEqual(exportNameSet.has('nsFunction'), true);
      assert.strictEqual(exportNameSet.has('TestInterface'), true);
      assert.strictEqual(exportNameSet.has('feature1'), false);
      assert.strictEqual(exportNameSet.has('feature2'), false);
      assert.strictEqual(exportNameSet.has('TestClass2'), false);
      assert.strictEqual(exportNameSet.has('prop4'), false);
      assert.strictEqual(exportNameSet.has('propObj'), false);
      assert.strictEqual(exportNameSet.has('innerProp'), false);
      assert.strictEqual(exportNameSet.has('TestClass3'), false);
      assert.strictEqual(exportNameSet.has('exportProp1'), false);
      assert.strictEqual(exportNameSet.has('exportPropObj'), false);
      assert.strictEqual(exportNameSet.has('exportInnerProp'), false);
      assert.strictEqual(exportNameSet.has('v2'), true);
      assert.strictEqual(exportNameSet.has('default'), true);
      assert.strictEqual(exportNameSet.has('t3'), true);
      assert.strictEqual(exportNameSet.has('outterElement1'), true);
      assert.strictEqual(exportNameSet.has('outterElement2'), true);
      assert.strictEqual(exportNameSet.has('o2'), true);
      assert.strictEqual(exportNameAndPropSet, undefined);
    });

    it('-enable-property-obfuscation', function () {
      let projectAndLibs: ReseverdSetForArkguard =
        readProjectPropertiesByCollectedPaths(fileList,
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
            mkeepFilesAndDependencies: new Set([
              "test/ut/utils/keep_export/exportFile1.ts"
            ]),
          }
        }, true);
      let exportNameAndPropSet = projectAndLibs.exportNameAndPropSet;
      let exportNameSet = projectAndLibs.exportNameSet;
      assert.strictEqual(exportNameAndPropSet.has('TestClass'), true);
      assert.strictEqual(exportNameAndPropSet.has('prop1'), true);
      assert.strictEqual(exportNameAndPropSet.has('prop2'), true);
      assert.strictEqual(exportNameAndPropSet.has('objProp'), true);
      assert.strictEqual(exportNameAndPropSet.has('innerProp2'), true);
      assert.strictEqual(exportNameAndPropSet.has('var1'), true);
      assert.strictEqual(exportNameAndPropSet.has('var2'), false);
      assert.strictEqual(exportNameAndPropSet.has('foo'), true);
      assert.strictEqual(exportNameAndPropSet.has('ns'), false);
      assert.strictEqual(exportNameAndPropSet.has('var3'), true);
      assert.strictEqual(exportNameAndPropSet.has('nsFunction'), true);
      assert.strictEqual(exportNameAndPropSet.has('TestInterface'), true);
      assert.strictEqual(exportNameAndPropSet.has('feature1'), true);
      assert.strictEqual(exportNameAndPropSet.has('feature2'), true);
      assert.strictEqual(exportNameAndPropSet.has('TestClass2'), false);
      assert.strictEqual(exportNameAndPropSet.has('prop4'), false);
      assert.strictEqual(exportNameAndPropSet.has('propObj'), false);
      assert.strictEqual(exportNameAndPropSet.has('innerProp'), false);
      assert.strictEqual(exportNameAndPropSet.has('TestClass3'), false);
      assert.strictEqual(exportNameAndPropSet.has('exportProp1'), true);
      assert.strictEqual(exportNameAndPropSet.has('exportPropObj'), true);
      assert.strictEqual(exportNameAndPropSet.has('exportInnerProp'), true);
      assert.strictEqual(exportNameAndPropSet.has('v2'), true);
      assert.strictEqual(exportNameAndPropSet.has('default'), true);
      assert.strictEqual(exportNameAndPropSet.has('t3'), true);
      assert.strictEqual(exportNameAndPropSet.has('outterElement1'), true);
      assert.strictEqual(exportNameAndPropSet.has('outterElement2'), false);
      assert.strictEqual(exportNameAndPropSet.has('o2'), true);
      assert.strictEqual(exportNameSet, undefined);
    });

    it('-enable-toplevel-obfuscation', function () {
      let projectAndLibs: ReseverdSetForArkguard =
        readProjectPropertiesByCollectedPaths(fileList,
        {
          mNameObfuscation: {
            mEnable: true,
            mReservedProperties: [],
            mRenameProperties: false,
            mKeepStringProperty: false,
            mTopLevel: true,
            mNameGeneratorType: NameGeneratorType.ORDERED,
            mReservedNames: [], 
            mReservedToplevelNames: []
          },
          mExportObfuscation: false,
          mKeepFileSourceCode: {
            mKeepSourceOfPaths: new Set(),
            mkeepFilesAndDependencies: new Set([
              "test/ut/utils/keep_export/exportFile1.ts"
            ]),
          }
        }, true);
      let exportNameAndPropSet = projectAndLibs.exportNameAndPropSet;
      let exportNameSet = projectAndLibs.exportNameSet;
      assert.strictEqual(exportNameAndPropSet, undefined);
      assert.strictEqual(exportNameSet, undefined);
    });

    it('-enable-toplevel-obfuscation -enable-export-obfuscation', function () {
      let projectAndLibs: ReseverdSetForArkguard =
        readProjectPropertiesByCollectedPaths(fileList,
        {
          mNameObfuscation: {
            mEnable: true,
            mReservedProperties: [],
            mRenameProperties: false,
            mKeepStringProperty: false,
            mTopLevel: true,
            mNameGeneratorType: NameGeneratorType.ORDERED,
            mReservedNames: [], 
            mReservedToplevelNames: []
          },
          mExportObfuscation: true,
          mKeepFileSourceCode: {
            mKeepSourceOfPaths: new Set(),
            mkeepFilesAndDependencies: new Set([
              "test/ut/utils/keep_export/exportFile1.ts"
            ]),
          }
        }, true);
      let exportNameAndPropSet = projectAndLibs.exportNameAndPropSet;
      let exportNameSet = projectAndLibs.exportNameSet;
      assert.strictEqual(exportNameSet.has('TestClass'), true);
      assert.strictEqual(exportNameSet.has('prop1'), false);
      assert.strictEqual(exportNameSet.has('prop2'), false);
      assert.strictEqual(exportNameSet.has('objProp'), false);
      assert.strictEqual(exportNameSet.has('innerProp2'), false);
      assert.strictEqual(exportNameSet.has('var1'), true);
      assert.strictEqual(exportNameSet.has('var2'), false);
      assert.strictEqual(exportNameSet.has('foo'), true);
      assert.strictEqual(exportNameSet.has('ns'), false);
      assert.strictEqual(exportNameSet.has('var3'), true);
      assert.strictEqual(exportNameSet.has('nsFunction'), true);
      assert.strictEqual(exportNameSet.has('TestInterface'), true);
      assert.strictEqual(exportNameSet.has('feature1'), false);
      assert.strictEqual(exportNameSet.has('feature2'), false);
      assert.strictEqual(exportNameSet.has('TestClass2'), false);
      assert.strictEqual(exportNameSet.has('prop4'), false);
      assert.strictEqual(exportNameSet.has('propObj'), false);
      assert.strictEqual(exportNameSet.has('innerProp'), false);
      assert.strictEqual(exportNameSet.has('TestClass3'), false);
      assert.strictEqual(exportNameSet.has('exportProp1'), false);
      assert.strictEqual(exportNameSet.has('exportPropObj'), false);
      assert.strictEqual(exportNameSet.has('exportInnerProp'), false);
      assert.strictEqual(exportNameSet.has('v2'), true);
      assert.strictEqual(exportNameSet.has('default'), true);
      assert.strictEqual(exportNameSet.has('t3'), true);
      assert.strictEqual(exportNameSet.has('outterElement1'), true);
      assert.strictEqual(exportNameSet.has('outterElement2'), true);
      assert.strictEqual(exportNameSet.has('o2'), true);
      assert.strictEqual(exportNameAndPropSet, undefined);
    });

    it('-enable-property-obfuscation -enable-export-obfuscation', function () {
      let projectAndLibs: ReseverdSetForArkguard =
        readProjectPropertiesByCollectedPaths(fileList,
        {
          mNameObfuscation: {
            mEnable: true,
            mReservedProperties: [],
            mRenameProperties: true,
            mKeepStringProperty: false,
            mTopLevel: false,
            mNameGeneratorType: NameGeneratorType.ORDERED,
            mReservedNames: [], 
            mReservedToplevelNames: []
          },
          mExportObfuscation: true,
          mKeepFileSourceCode: {
            mKeepSourceOfPaths: new Set(),
            mkeepFilesAndDependencies: new Set([
              "test/ut/utils/keep_export/exportFile1.ts"
            ]),
          }
        }, true);
      let exportNameAndPropSet = projectAndLibs.exportNameAndPropSet;
      let exportNameSet = projectAndLibs.exportNameSet;
      assert.strictEqual(exportNameSet.has('TestClass'), true);
      assert.strictEqual(exportNameSet.has('prop1'), false);
      assert.strictEqual(exportNameSet.has('prop2'), false);
      assert.strictEqual(exportNameSet.has('objProp'), false);
      assert.strictEqual(exportNameSet.has('innerProp2'), false);
      assert.strictEqual(exportNameSet.has('var1'), true);
      assert.strictEqual(exportNameSet.has('var2'), false);
      assert.strictEqual(exportNameSet.has('foo'), true);
      assert.strictEqual(exportNameSet.has('ns'), false);
      assert.strictEqual(exportNameSet.has('var3'), true);
      assert.strictEqual(exportNameSet.has('nsFunction'), true);
      assert.strictEqual(exportNameSet.has('TestInterface'), true);
      assert.strictEqual(exportNameSet.has('feature1'), false);
      assert.strictEqual(exportNameSet.has('feature2'), false);
      assert.strictEqual(exportNameSet.has('TestClass2'), false);
      assert.strictEqual(exportNameSet.has('prop4'), false);
      assert.strictEqual(exportNameSet.has('propObj'), false);
      assert.strictEqual(exportNameSet.has('innerProp'), false);
      assert.strictEqual(exportNameSet.has('TestClass3'), false);
      assert.strictEqual(exportNameSet.has('exportProp1'), false);
      assert.strictEqual(exportNameSet.has('exportPropObj'), false);
      assert.strictEqual(exportNameSet.has('exportInnerProp'), false);
      assert.strictEqual(exportNameSet.has('v2'), true);
      assert.strictEqual(exportNameSet.has('default'), true);
      assert.strictEqual(exportNameSet.has('t3'), true);
      assert.strictEqual(exportNameSet.has('outterElement1'), true);
      assert.strictEqual(exportNameSet.has('outterElement2'), true);
      assert.strictEqual(exportNameSet.has('o2'), true);
      assert.strictEqual(exportNameAndPropSet.has('TestClass'), true);
      assert.strictEqual(exportNameAndPropSet.has('prop1'), true);
      assert.strictEqual(exportNameAndPropSet.has('prop2'), true);
      assert.strictEqual(exportNameAndPropSet.has('objProp'), true);
      assert.strictEqual(exportNameAndPropSet.has('innerProp2'), true);
      assert.strictEqual(exportNameAndPropSet.has('var1'), true);
      assert.strictEqual(exportNameAndPropSet.has('var2'), false);
      assert.strictEqual(exportNameAndPropSet.has('foo'), true);
      assert.strictEqual(exportNameAndPropSet.has('ns'), false);
      assert.strictEqual(exportNameAndPropSet.has('var3'), true);
      assert.strictEqual(exportNameAndPropSet.has('nsFunction'), true);
      assert.strictEqual(exportNameAndPropSet.has('TestInterface'), true);
      assert.strictEqual(exportNameAndPropSet.has('feature1'), true);
      assert.strictEqual(exportNameAndPropSet.has('feature2'), true);
      assert.strictEqual(exportNameAndPropSet.has('TestClass2'), false);
      assert.strictEqual(exportNameAndPropSet.has('prop4'), false);
      assert.strictEqual(exportNameAndPropSet.has('propObj'), false);
      assert.strictEqual(exportNameAndPropSet.has('innerProp'), false);
      assert.strictEqual(exportNameAndPropSet.has('TestClass3'), false);
      assert.strictEqual(exportNameAndPropSet.has('exportProp1'), true);
      assert.strictEqual(exportNameAndPropSet.has('exportPropObj'), true);
      assert.strictEqual(exportNameAndPropSet.has('exportInnerProp'), true);
      assert.strictEqual(exportNameAndPropSet.has('v2'), true);
      assert.strictEqual(exportNameAndPropSet.has('default'), true);
      assert.strictEqual(exportNameAndPropSet.has('t3'), true);
      assert.strictEqual(exportNameAndPropSet.has('outterElement1'), true);
      assert.strictEqual(exportNameAndPropSet.has('outterElement2'), false);
      assert.strictEqual(exportNameAndPropSet.has('o2'), true);
    });

    it('-enable-property-obfuscation -enable-export-obfuscation -enable-toplevel-obfuscation', function () {
      let projectAndLibs: ReseverdSetForArkguard =
        readProjectPropertiesByCollectedPaths(fileList,
        {
          mNameObfuscation: {
            mEnable: true,
            mReservedProperties: [],
            mRenameProperties: true,
            mKeepStringProperty: false,
            mTopLevel: true,
            mNameGeneratorType: NameGeneratorType.ORDERED,
            mReservedNames: [], 
            mReservedToplevelNames: []
          },
          mExportObfuscation: true,
          mKeepFileSourceCode: {
            mKeepSourceOfPaths: new Set(),
            mkeepFilesAndDependencies: new Set([
              "test/ut/utils/keep_export/exportFile1.ts"
            ]),
          }
        }, true);
      let exportNameAndPropSet = projectAndLibs.exportNameAndPropSet;
      let exportNameSet = projectAndLibs.exportNameSet;
      assert.strictEqual(exportNameSet.has('TestClass'), true);
      assert.strictEqual(exportNameSet.has('prop1'), false);
      assert.strictEqual(exportNameSet.has('prop2'), false);
      assert.strictEqual(exportNameSet.has('objProp'), false);
      assert.strictEqual(exportNameSet.has('innerProp2'), false);
      assert.strictEqual(exportNameSet.has('var1'), true);
      assert.strictEqual(exportNameSet.has('var2'), false);
      assert.strictEqual(exportNameSet.has('foo'), true);
      assert.strictEqual(exportNameSet.has('ns'), false);
      assert.strictEqual(exportNameSet.has('var3'), true);
      assert.strictEqual(exportNameSet.has('nsFunction'), true);
      assert.strictEqual(exportNameSet.has('TestInterface'), true);
      assert.strictEqual(exportNameSet.has('feature1'), false);
      assert.strictEqual(exportNameSet.has('feature2'), false);
      assert.strictEqual(exportNameSet.has('TestClass2'), false);
      assert.strictEqual(exportNameSet.has('prop4'), false);
      assert.strictEqual(exportNameSet.has('propObj'), false);
      assert.strictEqual(exportNameSet.has('innerProp'), false);
      assert.strictEqual(exportNameSet.has('TestClass3'), false);
      assert.strictEqual(exportNameSet.has('exportProp1'), false);
      assert.strictEqual(exportNameSet.has('exportPropObj'), false);
      assert.strictEqual(exportNameSet.has('exportInnerProp'), false);
      assert.strictEqual(exportNameSet.has('v2'), true);
      assert.strictEqual(exportNameSet.has('default'), true);
      assert.strictEqual(exportNameSet.has('t3'), true);
      assert.strictEqual(exportNameSet.has('outterElement1'), true);
      assert.strictEqual(exportNameSet.has('outterElement2'), true);
      assert.strictEqual(exportNameSet.has('o2'), true);
      assert.strictEqual(exportNameAndPropSet.has('TestClass'), true);
      assert.strictEqual(exportNameAndPropSet.has('prop1'), true);
      assert.strictEqual(exportNameAndPropSet.has('prop2'), true);
      assert.strictEqual(exportNameAndPropSet.has('objProp'), true);
      assert.strictEqual(exportNameAndPropSet.has('innerProp2'), true);
      assert.strictEqual(exportNameAndPropSet.has('var1'), true);
      assert.strictEqual(exportNameAndPropSet.has('var2'), false);
      assert.strictEqual(exportNameAndPropSet.has('foo'), true);
      assert.strictEqual(exportNameAndPropSet.has('ns'), false);
      assert.strictEqual(exportNameAndPropSet.has('var3'), true);
      assert.strictEqual(exportNameAndPropSet.has('nsFunction'), true);
      assert.strictEqual(exportNameAndPropSet.has('TestInterface'), true);
      assert.strictEqual(exportNameAndPropSet.has('feature1'), true);
      assert.strictEqual(exportNameAndPropSet.has('feature2'), true);
      assert.strictEqual(exportNameAndPropSet.has('TestClass2'), false);
      assert.strictEqual(exportNameAndPropSet.has('prop4'), false);
      assert.strictEqual(exportNameAndPropSet.has('propObj'), false);
      assert.strictEqual(exportNameAndPropSet.has('innerProp'), false);
      assert.strictEqual(exportNameAndPropSet.has('TestClass3'), false);
      assert.strictEqual(exportNameAndPropSet.has('exportProp1'), true);
      assert.strictEqual(exportNameAndPropSet.has('exportPropObj'), true);
      assert.strictEqual(exportNameAndPropSet.has('exportInnerProp'), true);
      assert.strictEqual(exportNameAndPropSet.has('v2'), true);
      assert.strictEqual(exportNameAndPropSet.has('default'), true);
      assert.strictEqual(exportNameAndPropSet.has('t3'), true);
      assert.strictEqual(exportNameAndPropSet.has('outterElement1'), true);
      assert.strictEqual(exportNameAndPropSet.has('outterElement2'), false);
      assert.strictEqual(exportNameAndPropSet.has('o2'), true);
    });

    it('oh_modules test', function () {
      const ohModulesFileList: Set<string> = new Set([
        "test/ut/utils/oh_modules/exportFile1.ts"
      ]);
      let projectAndLibs: ReseverdSetForArkguard =
        readProjectPropertiesByCollectedPaths(ohModulesFileList,
        {
          mNameObfuscation: {
            mEnable: true,
            mReservedProperties: [],
            mRenameProperties: true,
            mKeepStringProperty: false,
            mTopLevel: true,
            mNameGeneratorType: NameGeneratorType.ORDERED,
            mReservedNames: [], 
            mReservedToplevelNames: []
          },
          mExportObfuscation: true,
          mKeepFileSourceCode: {
            mKeepSourceOfPaths: new Set(),
            mkeepFilesAndDependencies: new Set(),
          }
        }, true);
      let exportNameAndPropSet = projectAndLibs.exportNameAndPropSet;
      let exportNameSet = projectAndLibs.exportNameSet;
      assert.strictEqual(exportNameSet.has('ModuleNs'), true);
      assert.strictEqual(exportNameSet.has('nsProp1'), true);
      assert.strictEqual(exportNameSet.has('nsFunc'), true);
      assert.strictEqual(exportNameSet.has('ModuleClass'), true);
      assert.strictEqual(exportNameSet.has('classProp1'), false);
      assert.strictEqual(exportNameSet.has('objProp'), false);
      assert.strictEqual(exportNameSet.has('innerProp'), false);
      assert.strictEqual(exportNameSet.has('TestClass'), false);
      assert.strictEqual(exportNameSet.has('prop4'), false);
      assert.strictEqual(exportNameSet.has('propObj'), false);
      assert.strictEqual(exportNameSet.has('innerProp1'), false);
      assert.strictEqual(exportNameSet.has('TestClass2'), true);
      assert.strictEqual(exportNameSet.has('prop1'), false);
      assert.strictEqual(exportNameSet.has('objProp1'), false);
      assert.strictEqual(exportNameSet.has('innerProp2'), false);
      assert.strictEqual(exportNameSet.has('default'), true);
      assert.strictEqual(exportNameSet.has('mc'), true);
      assert.strictEqual(exportNameSet.has('otherElement1'), true);
      assert.strictEqual(exportNameSet.has('otherElement2'), true);
      assert.strictEqual(exportNameSet.has('o2'), true);
      assert.strictEqual(exportNameAndPropSet.has('ModuleNs'), false);
      assert.strictEqual(exportNameAndPropSet.has('nsProp1'), true);
      assert.strictEqual(exportNameAndPropSet.has('nsFunc'), true);
      assert.strictEqual(exportNameAndPropSet.has('ModuleClass'), false);
      assert.strictEqual(exportNameAndPropSet.has('classProp1'), true);
      assert.strictEqual(exportNameAndPropSet.has('objProp'), true);
      assert.strictEqual(exportNameAndPropSet.has('innerProp'), true);
      assert.strictEqual(exportNameAndPropSet.has('TestClass'), false);
      assert.strictEqual(exportNameAndPropSet.has('prop4'), false);
      assert.strictEqual(exportNameAndPropSet.has('propObj'), false);
      assert.strictEqual(exportNameAndPropSet.has('innerProp1'), false);
      assert.strictEqual(exportNameAndPropSet.has('TestClass2'), true);
      assert.strictEqual(exportNameAndPropSet.has('prop1'), true);
      assert.strictEqual(exportNameAndPropSet.has('objProp1'), true);
      assert.strictEqual(exportNameAndPropSet.has('innerProp2'), true);
      assert.strictEqual(exportNameAndPropSet.has('default'), true);
      assert.strictEqual(exportNameAndPropSet.has('mc'), true);
      assert.strictEqual(exportNameAndPropSet.has('otherElement1'), true);
      assert.strictEqual(exportNameAndPropSet.has('otherElement2'), false);
      assert.strictEqual(exportNameAndPropSet.has('o2'), true);
    });
  });
});