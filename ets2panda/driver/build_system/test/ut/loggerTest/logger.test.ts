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

import { Logger, LogDataFactory, LogData } from '../../../src/logger';
import { SubsystemCode, ErrorCode } from '../../../src/error_code';
import { BuildConfig, BUILD_TYPE, BUILD_MODE } from '../../../src/types';

function createMockBuildConfig(): BuildConfig {
  return {
    getHvigorConsoleLogger: jest.fn(() => ({
      printInfo: jest.fn(),
      printWarn: jest.fn(),
      printDebug: jest.fn(),
      printError: jest.fn(),
      printErrorAndExit: jest.fn(),
    })),
    packageName: 'mockpkg',
    moduleType: 'shared',
    moduleRootPath: '/mock/module',
    sourceRoots: [],
    byteCodeHar: false,
    plugins: {},
    compileFiles: [],
    dependentModuleList: [],
    buildType: BUILD_TYPE.BUILD,
    buildMode: BUILD_MODE.DEBUG,
    hasMainModule: true,
    arkts: {} as any,
    arktsGlobal: {} as any,
    declgenV1OutPath: undefined,
    declgenV2OutPath: undefined,
    declgenBridgeCodePath: undefined,
    buildSdkPath: '',
    loaderOutPath: '',
    cachePath: '',
    externalApiPaths: [],
    enableDeclgenEts2Ts: false,
  } as unknown as BuildConfig;
}

describe('Logger class', () => {
  let logger: Logger;

  beforeEach(() => {
    Logger.destroyInstance();
    logger = Logger.getInstance(createMockBuildConfig());
  });

  afterEach(() => {
    Logger.destroyInstance();
    jest.restoreAllMocks();
  });

  test('getInstance throws if not initialized', () => {
    Logger.destroyInstance();
    expect(() => Logger.getInstance()).toThrow('projectConfig is required for the first instantiation.');
  });

  test('getInstance returns singleton', () => {
    const logger1 = Logger.getInstance(createMockBuildConfig());
    const logger2 = Logger.getInstance();
    expect(logger1).toBe(logger2);
  });

  test('destroyInstance resets singleton', () => {
    const logger1 = Logger.getInstance(createMockBuildConfig());
    Logger.destroyInstance();
    const logger2 = Logger.getInstance(createMockBuildConfig());
    expect(logger1).not.toBe(logger2);
  });

  test('printInfo calls underlying logger', () => {
    const spy = jest.fn();
    (logger as any).loggerMap[SubsystemCode.BUILDSYSTEM].printInfo = spy;
    logger.printInfo('info');
    expect(spy).toHaveBeenCalledWith('info');
  });

  test('printWarn calls underlying logger', () => {
    const spy = jest.fn();
    (logger as any).loggerMap[SubsystemCode.BUILDSYSTEM].printWarn = spy;
    logger.printWarn('warn');
    expect(spy).toHaveBeenCalledWith('warn');
  });

  test('printDebug calls underlying logger', () => {
    const spy = jest.fn();
    (logger as any).loggerMap[SubsystemCode.BUILDSYSTEM].printDebug = spy;
    logger.printDebug('debug');
    expect(spy).toHaveBeenCalledWith('debug');
  });

  test('printError sets hasErrorOccurred and calls printError', () => {
    const spy = jest.fn();
    // insert '001' into the map, for test
    (logger as any).loggerMap['001'] = { printError: spy };
    const logData = LogDataFactory.newInstance('00100001' as ErrorCode, 'desc');
    logger.printError(logData);
    expect((logger as any).hasErrorOccurred).toBe(true);
    expect(spy).toHaveBeenCalledWith(logData);
  });

  test('printErrorAndExit sets hasErrorOccurred and calls printErrorAndExit', () => {
    const spy = jest.fn();
    (logger as any).loggerMap['001'] = { printErrorAndExit: spy };
    const logData = LogDataFactory.newInstance('00100001' as ErrorCode, 'desc');
    logger.printErrorAndExit(logData);
    expect((logger as any).hasErrorOccurred).toBe(true);
    expect(spy).toHaveBeenCalledWith(logData);
  });

  test('hasErrors and resetErrorFlag', () => {
    expect(logger.hasErrors()).toBe(false);
    (logger as any).hasErrorOccurred = true;
    expect(logger.hasErrors()).toBe(true);
    logger.resetErrorFlag();
    expect(logger.hasErrors()).toBe(false);
  });

  test('isValidErrorCode returns true for 8 digits', () => {
    expect((logger as any).isValidErrorCode('12345678')).toBe(true);
    expect((logger as any).isValidErrorCode('1234567')).toBe(false);
    expect((logger as any).isValidErrorCode('abcdefgh')).toBe(false);
  });

  test('getLoggerFromSubsystemCode throws for invalid code', () => {
    expect(() => (logger as any).getLoggerFromSubsystemCode('INVALID')).toThrow('Invalid subsystemCode.');
  });

  test('getLoggerFromSubsystemCode returns logger', () => {
    const fakeLogger = {
      printInfo: jest.fn(),
      printWarn: jest.fn(),
      printDebug: jest.fn(),
      printError: jest.fn(),
      printErrorAndExit: jest.fn()
    };
    (logger as any).loggerMap['FKLGR'] = fakeLogger;
    expect((logger as any).getLoggerFromSubsystemCode('FKLGR')).toBe(fakeLogger);
  });

  test('getLoggerFromErrorCode throws for invalid errorCode', () => {
    expect(() => (logger as any).getLoggerFromErrorCode('badcode')).toThrow('Invalid errorCode.');
  });

  test('getLoggerFromErrorCode returns logger for valid code', () => {
    const fakeLogger = {
      printInfo: jest.fn(),
      printWarn: jest.fn(),
      printDebug: jest.fn(),
      printError: jest.fn(),
      printErrorAndExit: jest.fn(),
    };
    (logger as any).loggerMap['001'] = fakeLogger;
    expect((logger as any).getLoggerFromErrorCode('00100001')).toBe(fakeLogger);
  });
});

describe('LogDataFactory and LogData', () => {
  test('LogDataFactory.newInstance creates LogData', () => {
    const logData = LogDataFactory.newInstance('00100001' as ErrorCode, 'desc', 'cause', 'pos', ['sol1', 'sol2'], { foo: 'bar' });
    expect(logData).toBeInstanceOf(LogData);
    expect(logData.code).toBe('00100001');
    expect(logData.description).toBe('desc');
    expect(logData.cause).toBe('cause');
    expect(logData.position).toBe('pos');
    expect(logData.solutions).toEqual(['sol1', 'sol2']);
    expect(logData.moreInfo).toEqual({ foo: 'bar' });
  });

  test('LogData.toString formats output', () => {
    const logData = LogDataFactory.newInstance('00100001' as ErrorCode, 'desc', 'cause', 'pos', ['sol1'], { foo: 'bar' });
    const str = logData.toString();
    expect(str).toContain('ERROR Code: 00100001 desc');
    expect(str).toContain('Error Message: cause pos');
    expect(str).toContain('> sol1');
    expect(str).toContain('More Info:');
    expect(str).toContain('FOO: bar');
  });

  test('LogData.toString omits empty fields', () => {
    const logData = LogDataFactory.newInstance('00100001' as ErrorCode, 'desc', '', '', [''], undefined);
    const str = logData.toString();
    expect(str).toContain('ERROR Code: 00100001 desc');
    expect(str).not.toContain('Error Message:');
    expect(str).not.toContain('More Info:');
  });
});
