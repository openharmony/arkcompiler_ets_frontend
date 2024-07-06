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

import { readProjectPropertiesByCollectedPaths } from '../../../src/common/ApiReader';
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
      let projectAndLibs: {projectAndLibsReservedProperties: string[]; libExportNames: string[]};
      projectAndLibs = readProjectPropertiesByCollectedPaths(fileList,
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
          }
        }, true);
      let reservedProperties = projectAndLibs.projectAndLibsReservedProperties;
      assert.strictEqual(reservedProperties.includes('BLOCK_PARAM1'), true);
      assert.strictEqual(reservedProperties.includes('BLOCK_PARAM2'), true);
      assert.strictEqual(reservedProperties.includes('ENUM_PARAM1'), true);
      assert.strictEqual(reservedProperties.includes('ENUM_PARAM2'), true);
      assert.strictEqual(reservedProperties.includes('NS_PARAM1'), true);
      assert.strictEqual(reservedProperties.includes('NS_PARAM2'), true);
      assert.strictEqual(reservedProperties.includes('EXPORT_PARAM1'), true);
      assert.strictEqual(reservedProperties.includes('EXPORT_PARAM2'), true);
    });

    it('-enable-property-obfuscation', function () {
      let projectAndLibs: {projectAndLibsReservedProperties: string[]; libExportNames: string[]};
      projectAndLibs = readProjectPropertiesByCollectedPaths(fileList,
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
      let reservedProperties = projectAndLibs.projectAndLibsReservedProperties;
      assert.strictEqual(reservedProperties.includes('BLOCK_PARAM1'), true);
      assert.strictEqual(reservedProperties.includes('BLOCK_PARAM2'), true);
      assert.strictEqual(reservedProperties.includes('ENUM_PARAM1'), true);
      assert.strictEqual(reservedProperties.includes('ENUM_PARAM2'), true);
      assert.strictEqual(reservedProperties.includes('NS_PARAM1'), true);
      assert.strictEqual(reservedProperties.includes('NS_PARAM2'), true);
      assert.strictEqual(reservedProperties.includes('EXPORT_PARAM1'), true);
      assert.strictEqual(reservedProperties.includes('EXPORT_PARAM2'), true);
    });

    it('-enable-export-obfuscation', function () {
      let projectAndLibs: {projectAndLibsReservedProperties: string[]; libExportNames: string[]};
      projectAndLibs = readProjectPropertiesByCollectedPaths(fileList,
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
      let reservedProperties = projectAndLibs.projectAndLibsReservedProperties;
      assert.strictEqual(reservedProperties.includes('BLOCK_PARAM1'), false);
      assert.strictEqual(reservedProperties.includes('BLOCK_PARAM2'), false);
      assert.strictEqual(reservedProperties.includes('ENUM_PARAM1'), false);
      assert.strictEqual(reservedProperties.includes('ENUM_PARAM2'), false);
      assert.strictEqual(reservedProperties.includes('NS_PARAM1'), false);
      assert.strictEqual(reservedProperties.includes('NS_PARAM2'), false);
      assert.strictEqual(reservedProperties.includes('EXPORT_PARAM1'), false);
      assert.strictEqual(reservedProperties.includes('EXPORT_PARAM2'), false);
    });
  });

  describe('test for -keep and export obfuscation', function () {
    const fileList: Set<string> = new Set([
      "test/ut/utils/keep_export/exportFile1.ts"
    ]);

    it('-enable-export-obfuscation', function () {
      let projectAndLibs: {projectAndLibsReservedProperties: string[]; libExportNames: string[]};
      projectAndLibs = readProjectPropertiesByCollectedPaths(fileList,
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
      let reservedNames = projectAndLibs.libExportNames;
      let reservedProperties = projectAndLibs.projectAndLibsReservedProperties;
      assert.strictEqual(reservedNames.includes('TestClass'), true);
      assert.strictEqual(reservedNames.includes('prop1'), false);
      assert.strictEqual(reservedNames.includes('prop2'), false);
      assert.strictEqual(reservedNames.includes('objProp'), false);
      assert.strictEqual(reservedNames.includes('innerProp2'), false);
      assert.strictEqual(reservedNames.includes('var1'), true);
      assert.strictEqual(reservedNames.includes('var2'), false);
      assert.strictEqual(reservedNames.includes('foo'), true);
      assert.strictEqual(reservedNames.includes('ns'), false);
      assert.strictEqual(reservedNames.includes('var3'), true);
      assert.strictEqual(reservedNames.includes('nsFunction'), true);
      assert.strictEqual(reservedNames.includes('TestInterface'), true);
      assert.strictEqual(reservedNames.includes('feature1'), false);
      assert.strictEqual(reservedNames.includes('feature2'), false);
      assert.strictEqual(reservedNames.includes('TestClass2'), false);
      assert.strictEqual(reservedNames.includes('prop4'), false);
      assert.strictEqual(reservedNames.includes('propObj'), false);
      assert.strictEqual(reservedNames.includes('innerProp'), false);
      assert.strictEqual(reservedNames.includes('TestClass3'), false);
      assert.strictEqual(reservedNames.includes('exportProp1'), false);
      assert.strictEqual(reservedNames.includes('exportPropObj'), false);
      assert.strictEqual(reservedNames.includes('exportInnerProp'), false);
      assert.strictEqual(reservedNames.includes('v2'), true);
      assert.strictEqual(reservedNames.includes('default'), true);
      assert.strictEqual(reservedNames.includes('t3'), true);
      assert.strictEqual(reservedNames.includes('outterElement1'), true);
      assert.strictEqual(reservedNames.includes('outterElement2'), true);
      assert.strictEqual(reservedNames.includes('o2'), true);
      assert.strictEqual(reservedProperties.length == 0, true);
    });

    it('-enable-property-obfuscation', function () {
      let projectAndLibs: {projectAndLibsReservedProperties: string[]; libExportNames: string[]};
      projectAndLibs = readProjectPropertiesByCollectedPaths(fileList,
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
      let reservedNames = projectAndLibs.libExportNames;
      let reservedProperties = projectAndLibs.projectAndLibsReservedProperties;
      assert.strictEqual(reservedProperties.includes('TestClass'), true);
      assert.strictEqual(reservedProperties.includes('prop1'), true);
      assert.strictEqual(reservedProperties.includes('prop2'), true);
      assert.strictEqual(reservedProperties.includes('objProp'), true);
      assert.strictEqual(reservedProperties.includes('innerProp2'), true);
      assert.strictEqual(reservedProperties.includes('var1'), true);
      assert.strictEqual(reservedProperties.includes('var2'), false);
      assert.strictEqual(reservedProperties.includes('foo'), true);
      assert.strictEqual(reservedProperties.includes('ns'), false);
      assert.strictEqual(reservedProperties.includes('var3'), true);
      assert.strictEqual(reservedProperties.includes('nsFunction'), true);
      assert.strictEqual(reservedProperties.includes('TestInterface'), true);
      assert.strictEqual(reservedProperties.includes('feature1'), true);
      assert.strictEqual(reservedProperties.includes('feature2'), true);
      assert.strictEqual(reservedProperties.includes('TestClass2'), false);
      assert.strictEqual(reservedProperties.includes('prop4'), false);
      assert.strictEqual(reservedProperties.includes('propObj'), false);
      assert.strictEqual(reservedProperties.includes('innerProp'), false);
      assert.strictEqual(reservedProperties.includes('TestClass3'), false);
      assert.strictEqual(reservedProperties.includes('exportProp1'), true);
      assert.strictEqual(reservedProperties.includes('exportPropObj'), true);
      assert.strictEqual(reservedProperties.includes('exportInnerProp'), true);
      assert.strictEqual(reservedProperties.includes('v2'), true);
      assert.strictEqual(reservedProperties.includes('default'), true);
      assert.strictEqual(reservedProperties.includes('t3'), true);
      assert.strictEqual(reservedProperties.includes('outterElement1'), true);
      assert.strictEqual(reservedProperties.includes('outterElement2'), false);
      assert.strictEqual(reservedProperties.includes('o2'), true);
      assert.strictEqual(reservedNames.length == 0, true);
    });

    it('-enable-toplevel-obfuscation', function () {
      let projectAndLibs: {projectAndLibsReservedProperties: string[]; libExportNames: string[]};
      projectAndLibs = readProjectPropertiesByCollectedPaths(fileList,
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
      let reservedNames = projectAndLibs.libExportNames;
      let reservedProperties = projectAndLibs.projectAndLibsReservedProperties;
      assert.strictEqual(reservedProperties.length == 0, true);
      assert.strictEqual(reservedNames.length == 0, true);
    });

    it('-enable-toplevel-obfuscation -enable-export-obfuscation', function () {
      let projectAndLibs: {projectAndLibsReservedProperties: string[]; libExportNames: string[]};
      projectAndLibs = readProjectPropertiesByCollectedPaths(fileList,
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
      let reservedNames = projectAndLibs.libExportNames;
      let reservedProperties = projectAndLibs.projectAndLibsReservedProperties;
      assert.strictEqual(reservedNames.includes('TestClass'), true);
      assert.strictEqual(reservedNames.includes('prop1'), false);
      assert.strictEqual(reservedNames.includes('prop2'), false);
      assert.strictEqual(reservedNames.includes('objProp'), false);
      assert.strictEqual(reservedNames.includes('innerProp2'), false);
      assert.strictEqual(reservedNames.includes('var1'), true);
      assert.strictEqual(reservedNames.includes('var2'), false);
      assert.strictEqual(reservedNames.includes('foo'), true);
      assert.strictEqual(reservedNames.includes('ns'), false);
      assert.strictEqual(reservedNames.includes('var3'), true);
      assert.strictEqual(reservedNames.includes('nsFunction'), true);
      assert.strictEqual(reservedNames.includes('TestInterface'), true);
      assert.strictEqual(reservedNames.includes('feature1'), false);
      assert.strictEqual(reservedNames.includes('feature2'), false);
      assert.strictEqual(reservedNames.includes('TestClass2'), false);
      assert.strictEqual(reservedNames.includes('prop4'), false);
      assert.strictEqual(reservedNames.includes('propObj'), false);
      assert.strictEqual(reservedNames.includes('innerProp'), false);
      assert.strictEqual(reservedNames.includes('TestClass3'), false);
      assert.strictEqual(reservedNames.includes('exportProp1'), false);
      assert.strictEqual(reservedNames.includes('exportPropObj'), false);
      assert.strictEqual(reservedNames.includes('exportInnerProp'), false);
      assert.strictEqual(reservedNames.includes('v2'), true);
      assert.strictEqual(reservedNames.includes('default'), true);
      assert.strictEqual(reservedNames.includes('t3'), true);
      assert.strictEqual(reservedNames.includes('outterElement1'), true);
      assert.strictEqual(reservedNames.includes('outterElement2'), true);
      assert.strictEqual(reservedNames.includes('o2'), true);
      assert.strictEqual(reservedProperties.length == 0, true);
    });

    it('-enable-property-obfuscation -enable-export-obfuscation', function () {
      let projectAndLibs: {projectAndLibsReservedProperties: string[]; libExportNames: string[]};
      projectAndLibs = readProjectPropertiesByCollectedPaths(fileList,
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
      let reservedNames = projectAndLibs.libExportNames;
      let reservedProperties = projectAndLibs.projectAndLibsReservedProperties;
      assert.strictEqual(reservedNames.includes('TestClass'), true);
      assert.strictEqual(reservedNames.includes('prop1'), false);
      assert.strictEqual(reservedNames.includes('prop2'), false);
      assert.strictEqual(reservedNames.includes('objProp'), false);
      assert.strictEqual(reservedNames.includes('innerProp2'), false);
      assert.strictEqual(reservedNames.includes('var1'), true);
      assert.strictEqual(reservedNames.includes('var2'), false);
      assert.strictEqual(reservedNames.includes('foo'), true);
      assert.strictEqual(reservedNames.includes('ns'), false);
      assert.strictEqual(reservedNames.includes('var3'), true);
      assert.strictEqual(reservedNames.includes('nsFunction'), true);
      assert.strictEqual(reservedNames.includes('TestInterface'), true);
      assert.strictEqual(reservedNames.includes('feature1'), false);
      assert.strictEqual(reservedNames.includes('feature2'), false);
      assert.strictEqual(reservedNames.includes('TestClass2'), false);
      assert.strictEqual(reservedNames.includes('prop4'), false);
      assert.strictEqual(reservedNames.includes('propObj'), false);
      assert.strictEqual(reservedNames.includes('innerProp'), false);
      assert.strictEqual(reservedNames.includes('TestClass3'), false);
      assert.strictEqual(reservedNames.includes('exportProp1'), false);
      assert.strictEqual(reservedNames.includes('exportPropObj'), false);
      assert.strictEqual(reservedNames.includes('exportInnerProp'), false);
      assert.strictEqual(reservedNames.includes('v2'), true);
      assert.strictEqual(reservedNames.includes('default'), true);
      assert.strictEqual(reservedNames.includes('t3'), true);
      assert.strictEqual(reservedNames.includes('outterElement1'), true);
      assert.strictEqual(reservedNames.includes('outterElement2'), true);
      assert.strictEqual(reservedNames.includes('o2'), true);
      assert.strictEqual(reservedProperties.includes('TestClass'), true);
      assert.strictEqual(reservedProperties.includes('prop1'), true);
      assert.strictEqual(reservedProperties.includes('prop2'), true);
      assert.strictEqual(reservedProperties.includes('objProp'), true);
      assert.strictEqual(reservedProperties.includes('innerProp2'), true);
      assert.strictEqual(reservedProperties.includes('var1'), true);
      assert.strictEqual(reservedProperties.includes('var2'), false);
      assert.strictEqual(reservedProperties.includes('foo'), true);
      assert.strictEqual(reservedProperties.includes('ns'), false);
      assert.strictEqual(reservedProperties.includes('var3'), true);
      assert.strictEqual(reservedProperties.includes('nsFunction'), true);
      assert.strictEqual(reservedProperties.includes('TestInterface'), true);
      assert.strictEqual(reservedProperties.includes('feature1'), true);
      assert.strictEqual(reservedProperties.includes('feature2'), true);
      assert.strictEqual(reservedProperties.includes('TestClass2'), false);
      assert.strictEqual(reservedProperties.includes('prop4'), false);
      assert.strictEqual(reservedProperties.includes('propObj'), false);
      assert.strictEqual(reservedProperties.includes('innerProp'), false);
      assert.strictEqual(reservedProperties.includes('TestClass3'), false);
      assert.strictEqual(reservedProperties.includes('exportProp1'), true);
      assert.strictEqual(reservedProperties.includes('exportPropObj'), true);
      assert.strictEqual(reservedProperties.includes('exportInnerProp'), true);
      assert.strictEqual(reservedProperties.includes('v2'), true);
      assert.strictEqual(reservedProperties.includes('default'), true);
      assert.strictEqual(reservedProperties.includes('t3'), true);
      assert.strictEqual(reservedProperties.includes('outterElement1'), true);
      assert.strictEqual(reservedProperties.includes('outterElement2'), false);
      assert.strictEqual(reservedProperties.includes('o2'), true);
    });

    it('-enable-property-obfuscation -enable-export-obfuscation -enable-toplevel-obfuscation', function () {
      let projectAndLibs: {projectAndLibsReservedProperties: string[]; libExportNames: string[]};
      projectAndLibs = readProjectPropertiesByCollectedPaths(fileList,
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
      let reservedNames = projectAndLibs.libExportNames;
      let reservedProperties = projectAndLibs.projectAndLibsReservedProperties;
      assert.strictEqual(reservedNames.includes('TestClass'), true);
      assert.strictEqual(reservedNames.includes('prop1'), false);
      assert.strictEqual(reservedNames.includes('prop2'), false);
      assert.strictEqual(reservedNames.includes('objProp'), false);
      assert.strictEqual(reservedNames.includes('innerProp2'), false);
      assert.strictEqual(reservedNames.includes('var1'), true);
      assert.strictEqual(reservedNames.includes('var2'), false);
      assert.strictEqual(reservedNames.includes('foo'), true);
      assert.strictEqual(reservedNames.includes('ns'), false);
      assert.strictEqual(reservedNames.includes('var3'), true);
      assert.strictEqual(reservedNames.includes('nsFunction'), true);
      assert.strictEqual(reservedNames.includes('TestInterface'), true);
      assert.strictEqual(reservedNames.includes('feature1'), false);
      assert.strictEqual(reservedNames.includes('feature2'), false);
      assert.strictEqual(reservedNames.includes('TestClass2'), false);
      assert.strictEqual(reservedNames.includes('prop4'), false);
      assert.strictEqual(reservedNames.includes('propObj'), false);
      assert.strictEqual(reservedNames.includes('innerProp'), false);
      assert.strictEqual(reservedNames.includes('TestClass3'), false);
      assert.strictEqual(reservedNames.includes('exportProp1'), false);
      assert.strictEqual(reservedNames.includes('exportPropObj'), false);
      assert.strictEqual(reservedNames.includes('exportInnerProp'), false);
      assert.strictEqual(reservedNames.includes('v2'), true);
      assert.strictEqual(reservedNames.includes('default'), true);
      assert.strictEqual(reservedNames.includes('t3'), true);
      assert.strictEqual(reservedNames.includes('outterElement1'), true);
      assert.strictEqual(reservedNames.includes('outterElement2'), true);
      assert.strictEqual(reservedNames.includes('o2'), true);
      assert.strictEqual(reservedProperties.includes('TestClass'), true);
      assert.strictEqual(reservedProperties.includes('prop1'), true);
      assert.strictEqual(reservedProperties.includes('prop2'), true);
      assert.strictEqual(reservedProperties.includes('objProp'), true);
      assert.strictEqual(reservedProperties.includes('innerProp2'), true);
      assert.strictEqual(reservedProperties.includes('var1'), true);
      assert.strictEqual(reservedProperties.includes('var2'), false);
      assert.strictEqual(reservedProperties.includes('foo'), true);
      assert.strictEqual(reservedProperties.includes('ns'), false);
      assert.strictEqual(reservedProperties.includes('var3'), true);
      assert.strictEqual(reservedProperties.includes('nsFunction'), true);
      assert.strictEqual(reservedProperties.includes('TestInterface'), true);
      assert.strictEqual(reservedProperties.includes('feature1'), true);
      assert.strictEqual(reservedProperties.includes('feature2'), true);
      assert.strictEqual(reservedProperties.includes('TestClass2'), false);
      assert.strictEqual(reservedProperties.includes('prop4'), false);
      assert.strictEqual(reservedProperties.includes('propObj'), false);
      assert.strictEqual(reservedProperties.includes('innerProp'), false);
      assert.strictEqual(reservedProperties.includes('TestClass3'), false);
      assert.strictEqual(reservedProperties.includes('exportProp1'), true);
      assert.strictEqual(reservedProperties.includes('exportPropObj'), true);
      assert.strictEqual(reservedProperties.includes('exportInnerProp'), true);
      assert.strictEqual(reservedProperties.includes('v2'), true);
      assert.strictEqual(reservedProperties.includes('default'), true);
      assert.strictEqual(reservedProperties.includes('t3'), true);
      assert.strictEqual(reservedProperties.includes('outterElement1'), true);
      assert.strictEqual(reservedProperties.includes('outterElement2'), false);
      assert.strictEqual(reservedProperties.includes('o2'), true);
    });

    it('oh_modules test', function () {
      const ohModulesFileList: Set<string> = new Set([
        "test/ut/utils/oh_modules/exportFile1.ts"
      ]);
      let projectAndLibs: {projectAndLibsReservedProperties: string[]; libExportNames: string[]};
      projectAndLibs = readProjectPropertiesByCollectedPaths(ohModulesFileList,
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
      let reservedNames = projectAndLibs.libExportNames;
      let reservedProperties = projectAndLibs.projectAndLibsReservedProperties;
      assert.strictEqual(reservedNames.includes('ModuleNs'), true);
      assert.strictEqual(reservedNames.includes('nsProp1'), true);
      assert.strictEqual(reservedNames.includes('nsFunc'), true);
      assert.strictEqual(reservedNames.includes('ModuleClass'), true);
      assert.strictEqual(reservedNames.includes('classProp1'), false);
      assert.strictEqual(reservedNames.includes('objProp'), false);
      assert.strictEqual(reservedNames.includes('innerProp'), false);
      assert.strictEqual(reservedNames.includes('TestClass'), false);
      assert.strictEqual(reservedNames.includes('prop4'), false);
      assert.strictEqual(reservedNames.includes('propObj'), false);
      assert.strictEqual(reservedNames.includes('innerProp1'), false);
      assert.strictEqual(reservedNames.includes('TestClass2'), true);
      assert.strictEqual(reservedNames.includes('prop1'), false);
      assert.strictEqual(reservedNames.includes('objProp1'), false);
      assert.strictEqual(reservedNames.includes('innerProp2'), false);
      assert.strictEqual(reservedNames.includes('default'), true);
      assert.strictEqual(reservedNames.includes('mc'), true);
      assert.strictEqual(reservedNames.includes('otherElement1'), true);
      assert.strictEqual(reservedNames.includes('otherElement2'), true);
      assert.strictEqual(reservedNames.includes('o2'), true);
      assert.strictEqual(reservedProperties.includes('ModuleNs'), false);
      assert.strictEqual(reservedProperties.includes('nsProp1'), true);
      assert.strictEqual(reservedProperties.includes('nsFunc'), true);
      assert.strictEqual(reservedProperties.includes('ModuleClass'), false);
      assert.strictEqual(reservedProperties.includes('classProp1'), true);
      assert.strictEqual(reservedProperties.includes('objProp'), true);
      assert.strictEqual(reservedProperties.includes('innerProp'), true);
      assert.strictEqual(reservedProperties.includes('TestClass'), false);
      assert.strictEqual(reservedProperties.includes('prop4'), false);
      assert.strictEqual(reservedProperties.includes('propObj'), false);
      assert.strictEqual(reservedProperties.includes('innerProp1'), false);
      assert.strictEqual(reservedProperties.includes('TestClass2'), true);
      assert.strictEqual(reservedProperties.includes('prop1'), true);
      assert.strictEqual(reservedProperties.includes('objProp1'), true);
      assert.strictEqual(reservedProperties.includes('innerProp2'), true);
      assert.strictEqual(reservedProperties.includes('default'), true);
      assert.strictEqual(reservedProperties.includes('mc'), true);
      assert.strictEqual(reservedProperties.includes('otherElement1'), true);
      assert.strictEqual(reservedProperties.includes('otherElement2'), false);
      assert.strictEqual(reservedProperties.includes('o2'), true);
    });
  });
});