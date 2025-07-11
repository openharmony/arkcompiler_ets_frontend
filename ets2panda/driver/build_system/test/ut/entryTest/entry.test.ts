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

import * as entryModule from '../../../src/entry';
import { BUILD_TYPE, BuildConfig, OHOS_MODULE_TYPE, BUILD_MODE } from '../../../src/types';
import { Logger } from '../../../src/logger';

jest.mock('../../../src/build/build_mode');
jest.mock('../../../src/build/build_framework_mode');
jest.mock('../../../src/logger');
jest.mock('../../../src/init/process_build_config', () => ({
  processBuildConfig: jest.fn((config) => config)
}));

beforeEach(() => {
  jest.clearAllMocks();
  process.exit = jest.fn() as any;
});

function testBuildTypeBranch() {
  const BuildMode = require('../../../src/build/build_mode').BuildMode;
  const BuildFrameworkMode = require('../../../src/build/build_framework_mode').BuildFrameworkMode;
  const mockBuildModeRun = jest.fn().mockResolvedValue(undefined);
  BuildMode.mockImplementation(() => {
    return {
      run: mockBuildModeRun,
      generateDeclaration: jest.fn()
    };
  });

  const mockLoggerHasErrors = jest.fn().mockReturnValue(false);
  Logger.getInstance = jest.fn().mockReturnValue({
    hasErrors: mockLoggerHasErrors,
    printInfo: jest.fn(),
    printError: jest.fn()
  });

  const mockConfig = {
    buildType: BUILD_TYPE.BUILD,
    packageName: 'test',
    compileFiles: ['test.ets'],
    enableDeclgenEts2Ts: false,
    frameworkMode: false,
    loaderOutPath: './dist',
    cachePath: './dist/cache',
    moduleType: OHOS_MODULE_TYPE.HAR,
    sourceRoots: ['./'],
    moduleRootPath: '/test/path',
    buildMode: BUILD_MODE.DEBUG
  } as BuildConfig;
  return {
    buildMode: BuildMode,
    frameworkMode: BuildFrameworkMode,
    mockBuildModeRun,
    mockConfig,
    execute: async () => {
      await entryModule.build(mockConfig);
      expect(BuildMode).toHaveBeenCalledWith(expect.objectContaining({
        buildType: BUILD_TYPE.BUILD,
        entryFiles: mockConfig.compileFiles
      }));
      expect(mockBuildModeRun).toHaveBeenCalled();
      expect(BuildFrameworkMode).not.toHaveBeenCalled();
    }
  };
}

function testFrameworkModeBranch() {
  const BuildMode = require('../../../src/build/build_mode').BuildMode;
  const BuildFrameworkMode = require('../../../src/build/build_framework_mode').BuildFrameworkMode;

  const mockFrameworkModeRun = jest.fn().mockResolvedValue(undefined);
  BuildFrameworkMode.mockImplementation(() => {
    return {
      run: mockFrameworkModeRun
    };
  });

  const mockLoggerHasErrors = jest.fn().mockReturnValue(false);
  Logger.getInstance = jest.fn().mockReturnValue({
    hasErrors: mockLoggerHasErrors,
    printInfo: jest.fn(),
    printError: jest.fn()
  });

  const mockConfig = {
    buildType: BUILD_TYPE.BUILD,
    packageName: 'test',
    compileFiles: ['test.ets'],
    enableDeclgenEts2Ts: false,
    frameworkMode: true,
    loaderOutPath: './dist',
    cachePath: './dist/cache',
    moduleType: OHOS_MODULE_TYPE.HAR,
    sourceRoots: ['./'],
    moduleRootPath: '/test/path',
    buildMode: BUILD_MODE.DEBUG
  } as BuildConfig;

  return {
    buildMode: BuildMode,
    frameworkMode: BuildFrameworkMode,
    mockFrameworkModeRun,
    mockConfig,
    mockLoggerHasErrors,
    execute: async () => {
      await entryModule.build(mockConfig);
      expect(BuildFrameworkMode).toHaveBeenCalledWith(expect.objectContaining({
        frameworkMode: true,
        entryFiles: mockConfig.compileFiles
      }));
      expect(mockFrameworkModeRun).toHaveBeenCalled();
      expect(BuildMode).not.toHaveBeenCalled();
      expect(process.exit).not.toHaveBeenCalled();
    }
  };
}

function testEnableDeclgenEts2TsBranch() {
  const BuildMode = require('../../../src/build/build_mode').BuildMode;
  const BuildFrameworkMode = require('../../../src/build/build_framework_mode').BuildFrameworkMode;
  const mockGenerateDeclaration = jest.fn().mockResolvedValue(undefined);
  BuildMode.mockImplementation(() => {
    return {
      run: jest.fn(),
      generateDeclaration: mockGenerateDeclaration
    };
  });

  Logger.getInstance = jest.fn().mockReturnValue({
    hasErrors: jest.fn().mockReturnValue(false),
    printInfo: jest.fn(),
    printError: jest.fn()
  });

  const mockConfig = {
    buildType: BUILD_TYPE.BUILD,
    packageName: 'test',
    compileFiles: ['test.ets'],
    enableDeclgenEts2Ts: true,
    frameworkMode: false,
    loaderOutPath: './dist',
    cachePath: './dist/cache',
    moduleType: OHOS_MODULE_TYPE.HAR,
    sourceRoots: ['./'],
    moduleRootPath: '/test/path',
    buildMode: BUILD_MODE.DEBUG
  } as BuildConfig;

  return {
    buildMode: BuildMode,
    frameworkMode: BuildFrameworkMode,
    mockGenerateDeclaration,
    mockConfig,
    execute: async () => {
      await entryModule.build(mockConfig);
      expect(BuildMode).toHaveBeenCalledWith(expect.objectContaining({
        enableDeclgenEts2Ts: true,
        entryFiles: mockConfig.compileFiles
      }));
      expect(mockGenerateDeclaration).toHaveBeenCalled();
      expect(BuildFrameworkMode).not.toHaveBeenCalled();
    }
  };
}

function testNoMatchingBranch() {
  const BuildMode = require('../../../src/build/build_mode').BuildMode;
  const BuildFrameworkMode = require('../../../src/build/build_framework_mode').BuildFrameworkMode;
  BuildMode.mockReset();
  BuildFrameworkMode.mockReset();
  const mockBuildModeRun = jest.fn();
  const mockGenerateDeclaration = jest.fn();
  const mockLoggerHasErrors = jest.fn()
    .mockReturnValueOnce(true) 
    .mockReturnValueOnce(false);
  Logger.getInstance = jest.fn().mockReturnValue({
    hasErrors: mockLoggerHasErrors,
    printInfo: jest.fn(),
    printError: jest.fn()
  });
  const clean = jest.fn();
  jest.mock('../../../src/entry.ts', () => ({
    clean: clean
  }));
  const mockConfig = {
    buildType: BUILD_TYPE.PREVIEW,
    packageName: 'test',
    compileFiles: ['test.ets'],
    enableDeclgenEts2Ts: false,
    frameworkMode: true,
    loaderOutPath: './dist',
    cachePath: './dist/cache',
    moduleType: OHOS_MODULE_TYPE.HAR,
    sourceRoots: ['./'],
    moduleRootPath: '/test/path',
    buildMode: BUILD_MODE.DEBUG
  } as BuildConfig;
  return {
    buildMode: BuildMode,
    frameworkMode: BuildFrameworkMode,
    mockBuildModeRun,
    mockGenerateDeclaration,
    mockConfig,
    mockLoggerHasErrors,
    clean,
    execute: async () => {
      await entryModule.build(mockConfig);
      expect(mockLoggerHasErrors).toHaveBeenCalled();
      jest.clearAllMocks();
      await entryModule.build(mockConfig);
      expect(BuildMode).not.toHaveBeenCalled();
    }
  };
}

// Test the functions of the entry.ts file
describe('test entry.ts file api', () => {
  test('test build function BUILD_TYPE.BUILD branch', async () => {
    const testCase = testBuildTypeBranch();
    await testCase.execute();
  });

  test('test build function frameworkMode branch', async () => {
    const testCase = testFrameworkModeBranch();
    await testCase.execute();
  });

  test('test build function enableDeclgenEts2Ts branch', async () => {
    const testCase = testEnableDeclgenEts2TsBranch();
    await testCase.execute();
  });

  test('test build function no matching branch', async () => {
    const testCase = testNoMatchingBranch();
    await testCase.execute();
  });
});
