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

import { PluginDriver, PluginHook} from '../../../src/plugins/plugins_driver';

jest.mock('../../../src/plugins/plugins_driver', () => {
  const actual = jest.requireActual('../../../src/plugins/plugins_driver');
  
  function MockPluginDriver(this: any, ...args: any[]) {
    this.plugins = {};
  }
  
  MockPluginDriver.prototype = actual.PluginDriver.prototype;
  
  Object.getOwnPropertyNames(actual.PluginDriver).forEach((key) => {
    if (!['prototype', 'length', 'name'].includes(key)) {
      (MockPluginDriver as any)[key] = (actual.PluginDriver as any)[key];
    }
  });

  return {
    ...actual,
    PluginDriver: MockPluginDriver,
    __esModule: true,
  };
});
type PluginHandlerFunction = () => void;

type PluginHandlerObject = {
  order: 'pre' | 'post' | undefined
  handler: PluginHandlerFunction
};
type PluginHandler = PluginHandlerFunction | PluginHandlerObject;
interface Plugins {
  name: string,
  afterNew?: PluginHandler,
  parsed?: PluginHandler,
  scopeInited?: PluginHandler,
  checked?: PluginHandler,
  lowered?: PluginHandler,
  asmGenerated?: PluginHandler,
  binGenerated?: PluginHandler,
  clean?: PluginHandler,
}

jest.mock('path/to/valid/plugin', () => {
  return {
    validPlugin: () => { },
  };
}, { virtual: true });

jest.mock('path/to/invalid/plugin', () => {
  return {
    invalidPlugin: {},
  };
}, { virtual: true });

describe('test plugins_driver.ts file api', () => {
  test('test initPlugins001', () => {
    test_initPlugins001();
  });

  test('test initPlugins002', () => {
    test_initPlugins002();
  });

  test('test getSortedPlugins', () => {
    test_getSortedPlugins();
  });
});

function test_initPlugins001() {
  const driver = new PluginDriver();
  const result = driver.initPlugins(undefined as any);
  expect(result).toBeUndefined();
}

function test_initPlugins002() {
  const driver = new PluginDriver();
  const mockProjectConfig = {
    plugins: {
      invalidPlugin: 'path/to/invalid/plugin',
    },
    compileFiles: [],
    dependentModuleList: [],
    buildType: 'build',
    buildMode: 'debug',
    packageName: 'test',
    moduleRootPath: '/test/path',
    sourceRoots: ['./'],
    loaderOutPath: './dist',
    cachePath: './dist/cache',
    moduleType: 'har',
    hasMainModule: false,
    byteCodeHar: false,
    arkts: {},
    arktsGlobal: {},
    declgenV1OutPath: './dist/declgen',
    declgenV2OutPath: './dist/declgen/v2',
    buildSdkPath: './sdk',
    externalApiPaths: [],
    enableDeclgenEts2Ts: false
  };

  let error;
  try {
    driver.initPlugins(mockProjectConfig as any);
  } catch (e) {
    error = e;
  }

  expect(error).not.toBeUndefined();
}

function test_getSortedPlugins() {
  const driver = new PluginDriver();
  const hook = PluginHook.PARSED;

  driver['allPlugins'] = new Map<string, Plugins>([
    [
      'plugin1',
      {
        name: 'plugin1',
        parsed: { order: 'pre', handler: jest.fn() },
      },
    ],
    [
      'plugin2',
      {
        name: 'plugin2',
        parsed: jest.fn(),
      },
    ],
    [
      'plugin3',
      {
        name: 'plugin3',
        parsed: { order: 'post', handler: jest.fn() },
      },
    ],
  ]);

  const result = driver['getSortedPlugins'](hook);

  expect(result).toEqual([
    { name: 'plugin1', handler: expect.any(Function) },
    { name: 'plugin2', handler: expect.any(Function) },
    { name: 'plugin3', handler: expect.any(Function) },
  ]);
}
