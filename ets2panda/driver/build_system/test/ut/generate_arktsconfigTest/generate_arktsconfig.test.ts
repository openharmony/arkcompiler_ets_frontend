/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

import * as fs from 'fs';
import path from 'path';
import { ArkTSConfigGenerator } from '../../../src/build/generate_arktsconfig';
import { ModuleInfo } from '../../../src/types';

jest.mock('../../../src/build/generate_arktsconfig', () => {
  const actual = jest.requireActual('../../../src/build/generate_arktsconfig');
  function MockArkTSConfigGenerator(this: any, ...args: any[]) { }
  MockArkTSConfigGenerator.prototype = actual.ArkTSConfigGenerator.prototype;
  Object.getOwnPropertyNames(actual.ArkTSConfigGenerator).forEach((key) => {
    if (!['prototype', 'length', 'name'].includes(key)) {
      (MockArkTSConfigGenerator as any)[key] = actual.ArkTSConfigGenerator[key];
    }
  });

  return {
    ArkTSConfigGenerator: MockArkTSConfigGenerator,
    __esModule: true,
  };
});

describe('test generate_arktsconfig.ts file api', () => {
  test('test getInstance', () => {
    expect(() => {
      ArkTSConfigGenerator.getInstance();
    }).toThrow('buildConfig and moduleInfos is required for the first instantiation of ArkTSConfigGenerator.');
  });

  test('test getOhmurl', () => {
    test_getOhmurl();
  });

  test('test writeArkTSConfigFile', () => {
    test_writeArkTSConfigFile();
  });
});


function test_writeArkTSConfigFile() {
  // Mock getInstance to bypass the private constructor
  jest.spyOn(ArkTSConfigGenerator, 'getInstance').mockImplementation(() => {
    return Object.create(ArkTSConfigGenerator.prototype);
  });
  const generator = ArkTSConfigGenerator.getInstance();
  (generator as any).logger = {
    printWarn: jest.fn(),
    printErrorAndExit: jest.fn(() => { throw new Error('exit'); })
  };
  (generator as any).moduleInfos = new Map();

  const moduleInfo: ModuleInfo = {
    isMainModule: true,
    packageName: 'test-pkg',
    moduleRootPath: '/tmp/test-module',
    moduleType: 'type',
    sourceRoots: [],
    entryFile: 'index.ets',
    arktsConfigFile: 'arktsconfig.json',
    compileFileInfos: [],
    declgenV1OutPath: undefined,
    declgenV2OutPath: undefined,
    declgenBridgeCodePath: undefined,
    byteCodeHar: false,
    staticDepModuleInfos: new Map(),
    dynamicDepModuleInfos: new Map(),
  };

  expect(() => {
    generator.writeArkTSConfigFile(moduleInfo, false);
  }).toThrow('exit');
}

function test_getOhmurl() {
  const moduleInfo: ModuleInfo = {
    isMainModule: true,
    packageName: 'example-package',
    moduleRootPath: '/path/to/module',
    moduleType: 'type',
    sourceRoots: ['/src'],
    entryFile: 'index.ts',
    arktsConfigFile: 'arktsconfig.json',
    compileFileInfos: [],
    declgenV1OutPath: undefined,
    declgenV2OutPath: undefined,
    declgenBridgeCodePath: undefined,
    byteCodeHar: false,
    staticDepModuleInfos: new Map(),
    dynamicDepModuleInfos: new Map(),
  };

  const filePath = '';
  const expectedUrl = 'example-package/';
  jest.spyOn(ArkTSConfigGenerator, 'getInstance').mockImplementation(() => {
    return Object.create(ArkTSConfigGenerator.prototype);
  });
  const generator = ArkTSConfigGenerator.getInstance();

  expect((generator as any).getOhmurl(filePath, moduleInfo)).toBe(expectedUrl);
}
