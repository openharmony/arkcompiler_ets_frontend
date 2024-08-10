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

import mocha from 'mocha';
import path from 'path';
import fs from "fs";
import { expect } from 'chai';

import { ObConfigResolver } from '../../../src/initialization/ConfigResolver';
import { UnobfuscationCollections } from '../../../src/utils/CommonCollections'

const OBFUSCATE_TESTDATA_DIR = path.resolve(__dirname, '../testdata/system_api_obfuscation');

describe('1: test Api getSystemApiCache', function() {
 mocha.it('1-1: test getSystemApiCache: -enable-property-obfuscation', function () {
    let obfuscationCacheDir = path.join(OBFUSCATE_TESTDATA_DIR, 'property');
    let obfuscationOptions = {
      'selfConfig': {
        'ruleOptions': {
          'enable': true,
          'rules': [ 
            path.join(OBFUSCATE_TESTDATA_DIR, 'property/property.txt')
          ]
        },
        'consumerRules': [],
      },
      'dependencies': {
        'libraries': [],
        'hars': []
      },
      'obfuscationCacheDir': obfuscationCacheDir,
      'sdkApis': [
        path.join(OBFUSCATE_TESTDATA_DIR, 'system_api.d.ts')
      ]
    };
    let projectConfig = {
      obfuscationOptions,
      compileHar: false
    };
    const obConfig: ObConfigResolver =  new ObConfigResolver(projectConfig, undefined);
    obConfig.resolveObfuscationConfigs();
    const reservedSdkApiForProp = UnobfuscationCollections.reservedSdkApiForProp;
    const reservedSdkApiForGlobal = UnobfuscationCollections.reservedSdkApiForGlobal;

    expect(reservedSdkApiForProp.size == 8).to.be.true;
    expect(reservedSdkApiForProp.has('TestClass')).to.be.true;
    expect(reservedSdkApiForProp.has('para1')).to.be.true;
    expect(reservedSdkApiForProp.has('para2')).to.be.true;
    expect(reservedSdkApiForProp.has('foo')).to.be.true;
    expect(reservedSdkApiForProp.has('TestFunction')).to.be.true;
    expect(reservedSdkApiForProp.has('funcPara1')).to.be.true;
    expect(reservedSdkApiForProp.has('funcPara2')).to.be.true;
    expect(reservedSdkApiForProp.has('ns')).to.be.true;
    expect(reservedSdkApiForGlobal.size == 0).to.be.true;
    UnobfuscationCollections.clear();

    let systemApiPath = obfuscationCacheDir + '/systemApiCache.json';
    const data = fs.readFileSync(systemApiPath, 'utf8');
    const systemApiContent = JSON.parse(data);

    expect(systemApiContent.ReservedPropertyNames.length == 8).to.be.true;
    expect(systemApiContent.ReservedPropertyNames.includes('TestClass')).to.be.true;
    expect(systemApiContent.ReservedPropertyNames.includes('para1')).to.be.true;
    expect(systemApiContent.ReservedPropertyNames.includes('para2')).to.be.true;
    expect(systemApiContent.ReservedPropertyNames.includes('foo')).to.be.true;
    expect(systemApiContent.ReservedPropertyNames.includes('TestFunction')).to.be.true;
    expect(systemApiContent.ReservedPropertyNames.includes('funcPara1')).to.be.true;
    expect(systemApiContent.ReservedPropertyNames.includes('funcPara2')).to.be.true;
    expect(systemApiContent.ReservedPropertyNames.includes('ns')).to.be.true;
    expect(systemApiContent.ReservedGlobalNames == undefined).to.be.true;

    fs.unlinkSync(systemApiPath);
  });

  mocha.it('1-2: test getSystemApiCache: -enable-export-obfuscation', function () {
    let obfuscationCacheDir = path.join(OBFUSCATE_TESTDATA_DIR, 'export');
    let obfuscationOptions = {
      'selfConfig': {
        'ruleOptions': {
          'enable': true,
          'rules': [ 
            path.join(OBFUSCATE_TESTDATA_DIR, 'export/export.txt')
          ]
        },
        'consumerRules': [],
      },
      'dependencies': {
        'libraries': [],
        'hars': []
      },
      'obfuscationCacheDir': obfuscationCacheDir,
      'sdkApis': [
        path.join(OBFUSCATE_TESTDATA_DIR, 'system_api.d.ts')
      ]
    };
    let projectConfig = {
      obfuscationOptions,
      compileHar: false
    };
    const obConfig: ObConfigResolver =  new ObConfigResolver(projectConfig, undefined);
    obConfig.resolveObfuscationConfigs();
    const reservedSdkApiForProp = UnobfuscationCollections.reservedSdkApiForProp;
    const reservedSdkApiForGlobal = UnobfuscationCollections.reservedSdkApiForGlobal;

    expect(reservedSdkApiForProp.size == 0).to.be.true;
    expect(reservedSdkApiForGlobal.size == 0).to.be.true;
    UnobfuscationCollections.clear();

    let systemApiPath = obfuscationCacheDir + '/systemApiCache.json';
    const noSystemApi = fs.existsSync(systemApiPath);

    expect(noSystemApi).to.be.false;
  });

  mocha.it('1-3: test getSystemApiCache: -enable-export-obfuscation -enable-toplevel-obfuscation', function () {
    let obfuscationCacheDir = path.join(OBFUSCATE_TESTDATA_DIR, 'export_toplevel');
    let obfuscationOptions = {
      'selfConfig': {
        'ruleOptions': {
          'enable': true,
          'rules': [ 
            path.join(OBFUSCATE_TESTDATA_DIR, 'export_toplevel/export_toplevel.txt')
          ]
        },
        'consumerRules': [],
      },
      'dependencies': {
        'libraries': [],
        'hars': []
      },
      'obfuscationCacheDir': obfuscationCacheDir,
      'sdkApis': [
        path.join(OBFUSCATE_TESTDATA_DIR, 'system_api.d.ts')
      ]
    };
    let projectConfig = {
      obfuscationOptions,
      compileHar: false
    };
    const obConfig: ObConfigResolver =  new ObConfigResolver(projectConfig, undefined);
    obConfig.resolveObfuscationConfigs();
    const reservedSdkApiForProp = UnobfuscationCollections.reservedSdkApiForProp;
    const reservedSdkApiForGlobal = UnobfuscationCollections.reservedSdkApiForGlobal;

    expect(reservedSdkApiForProp.size == 0).to.be.true;
    expect(reservedSdkApiForGlobal.size == 3).to.be.true;
    expect(reservedSdkApiForGlobal.has('TestClass')).to.be.true;
    expect(reservedSdkApiForGlobal.has('TestFunction')).to.be.true;
    expect(reservedSdkApiForGlobal.has('ns')).to.be.true;
    UnobfuscationCollections.clear();

    let systemApiPath = obfuscationCacheDir + '/systemApiCache.json';
    const data = fs.readFileSync(systemApiPath, 'utf8');
    const systemApiContent = JSON.parse(data);

    expect(systemApiContent.ReservedPropertyNames == undefined).to.be.true;
    expect(systemApiContent.ReservedGlobalNames.length == 3).to.be.true;
    expect(systemApiContent.ReservedGlobalNames.includes('TestClass')).to.be.true;
    expect(systemApiContent.ReservedGlobalNames.includes('TestFunction')).to.be.true;
    expect(systemApiContent.ReservedGlobalNames.includes('ns')).to.be.true;

    fs.unlinkSync(systemApiPath);
  });
})