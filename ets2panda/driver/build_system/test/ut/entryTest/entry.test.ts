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
import * as entryModule from '../../../src/entry';
import { BuildConfig } from '../../../src/types';

beforeEach(() => {
  jest.clearAllMocks();

  process.exit = jest.fn() as any;

});

function main(configFilePath?: string): void {
  const buildConfigPath = configFilePath;

  const projectConfig: BuildConfig = JSON.parse(fs.readFileSync(buildConfigPath!, 'utf-8'));

  entryModule.build(projectConfig);
}

describe('test entry.ts file api', () => {
  test('test build001', () => {
    test_build001();
  });
  test('test build002', () => {
    test_build002();
  });
  test('test build003', () => {
    test_build003();
  });
  test('test build004', () => {
    test_build004();
  });
});

function test_build001() {
  const buildSpy = jest.spyOn(entryModule, 'build');
  const buildConfigPath = "test/ut/mock/demo_1.2_dep_hsp1.2/build_config3.json";
  main(buildConfigPath);
  expect(buildSpy).toHaveBeenCalledWith(expect.objectContaining({
    buildType: 'build'
  }));
}

function test_build002() {
  const buildSpy = jest.spyOn(entryModule, 'build');
  const buildConfigPath = "test/ut/mock/demo_1.2_dep_hsp1.2/build_config.json";
  main(buildConfigPath);
  expect(buildSpy).toHaveBeenCalledWith(expect.objectContaining({
    buildType: 'build1'
  }));
}

function test_build003() {
  const buildSpy = jest.spyOn(entryModule, 'build');
  const buildConfigPath = "test/ut/mock/demo_1.2_dep_hsp1.2/build_config1.json";
  main(buildConfigPath);
  expect(buildSpy).toHaveBeenCalledWith(expect.objectContaining({
    frameworkMode: true,
  }));
}

function test_build004() {
  const buildSpy = jest.spyOn(entryModule, 'build');
  const buildConfigPath = "test/ut/mock/demo_1.2_dep_hsp1.2/build_config2.json";
  main(buildConfigPath);
  expect(buildSpy).toHaveBeenCalledWith(expect.objectContaining({
    enableDeclgenEts2Ts: true,
  }));
}
