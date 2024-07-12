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
});