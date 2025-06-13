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


import { ensurePathExists, getFileHash } from '../../../src/utils';
import * as fs from 'fs';
import * as path from 'path';
import {
  ErrorCode,
} from '../../../src/error_code';
import {
  isWindows, isLinux, isMac,
  changeFileExtension, changeDeclgenFileExtension,
 toUnixPath, readFirstLineSync, safeRealpath
} from '../../../src/utils';
import { DECL_ETS_SUFFIX } from '../../../src/pre_define';

describe('test getFileHash', () => {
  const testFile = path.join(__dirname, 'testFile.txt');

  beforeEach(() => {
    fs.writeFileSync(testFile, 'Hello, World!', 'utf8');
  });

  afterEach(() => {
    if (fs.existsSync(testFile)) {
      fs.unlinkSync(testFile);
    }
  });

  it('test getFileHash001', () => {
    test_getFileHash001(testFile);
  });

  it('test getFileHash002', () => {
    test_getFileHash002();
  });
});

describe('test ensurePathExists', () => {
  const testDir = path.join(__dirname, 'testDir');

  beforeEach(() => {
    if (fs.existsSync(testDir)) {
      fs.rmdirSync(testDir, { recursive: true });
    }
  });

  afterEach(() => {
    if (fs.existsSync(testDir)) {
      fs.rmdirSync(testDir, { recursive: true });
    }
  });

  it('test ensurePathExists001', () => {
    test_ensurePathExists001(testDir);
  });

  it('test ensurePathExists002', () => {
    test_ensurePathExists002(testDir);
  });
});

describe('utils', () => {
  describe('isWindows/isLinux/isMac', () => {
    it('should detect Linux', () => {
      expect(isLinux()).toBe(true);
      expect(isWindows()).toBe(false);
      expect(isMac()).toBe(false);
    });
  });

  describe('changeFileExtension', () => {
    it('should change extension when originExt is empty', () => {
      expect(changeFileExtension('a/b/c.txt', '.js')).toBe('a/b/c.js');
    });
    it('should change extension when originExt is provided', () => {
      expect(changeFileExtension('a/b/c.txt', '.js', '.txt')).toBe('a/b/c.js');
    });
  });

  describe('changeDeclgenFileExtension', () => {
    it('should use DECL_ETS_SUFFIX branch', () => {
      const file = `foo${DECL_ETS_SUFFIX}`;
      expect(changeDeclgenFileExtension(file, '.ts')).toBe('foo.ts');
    });
    it('should use default branch', () => {
      expect(changeDeclgenFileExtension('foo.ets', '.ts')).toBe('foo.ts');
    });
  });

  describe('toUnixPath', () => {
    it('should replace backslashes with slashes', () => {
      expect(toUnixPath('a\\b\\c')).toBe('a/b/c');
    });
  });
});

describe('readFirstLineSync', () => {
  const testFile = path.join(__dirname, 'testReadFirstLine.txt');
  
  afterEach(() => {
    if (fs.existsSync(testFile)) {
      fs.unlinkSync(testFile);
    }
  });
  
  it('should read first line of a file with single line', () => {
    const content = 'Hello, World!';
    fs.writeFileSync(testFile, content, 'utf8');
    
    const result = readFirstLineSync(testFile);
    expect(result).toBe('Hello, World!');
  });
  
  it('should read only first line of a multi-line file', () => {
    const content = 'First line\nSecond line\nThird line';
    fs.writeFileSync(testFile, content, 'utf8');
    
    const result = readFirstLineSync(testFile);
    expect(result).toBe('First line');
  });
  
  it('should trim the first line', () => {
    const content = '  Whitespace around  \nSecond line';
    fs.writeFileSync(testFile, content, 'utf8');
    
    const result = readFirstLineSync(testFile);
    expect(result).toBe('Whitespace around');
  });
  
  it('should handle CRLF line endings', () => {
    const content = 'Windows line\r\nSecond line';
    fs.writeFileSync(testFile, content, 'utf8');
    
    const result = readFirstLineSync(testFile);
    expect(result).toBe('Windows line');
  });
  
  it('should return empty string for empty file', () => {
    fs.writeFileSync(testFile, '', 'utf8');
    
    const result = readFirstLineSync(testFile);
    expect(result).toBe('');
  });
  
  it('should throw error for non-existent file', () => {
    const nonExistentFile = path.join(__dirname, 'nonExistentFile.txt');
    
    expect(() => {
      readFirstLineSync(nonExistentFile);
    }).toThrow();
  });
});

describe('safeRealpath', () => {
  it('test safeRealpath001', () => {
    const testDir = path.join(__dirname);
    const mockLogger = { printInfo: jest.fn(), printError: jest.fn() };
    
    const result = safeRealpath(testDir, mockLogger as any);
    expect(result).toBe(fs.realpathSync(testDir));
    expect(mockLogger.printError).not.toHaveBeenCalled();
  });

  it('test safeRealpath002', () => {
    const nonExistentPath = path.join(__dirname, 'non-existent-directory');
    const mockLogger = { printInfo: jest.fn(), printError: jest.fn() };
    
    expect(() => {
      safeRealpath(nonExistentPath, mockLogger as any);
    }).toThrow();
    
    expect(mockLogger.printError).toHaveBeenCalledWith(
    expect.objectContaining({
      code: ErrorCode.BUILDSYSTEM_PATH_RESOLVE_FAIL,
      description: expect.stringContaining(`Error resolving path "${nonExistentPath}"`)
    })
  );
  });
});

function test_getFileHash001(testFile: string) {
  const hash = getFileHash(testFile);
  expect(hash).toBe('dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f');
}

function test_getFileHash002() {
  let error: Error | undefined;
  try {
    getFileHash('/nonexistent/file.txt');
  } catch (e) {
    error = e as Error;
  }
  expect(error).not.toBe(undefined);
}

function test_ensurePathExists001(testDir: string) {
  expect(fs.existsSync(testDir)).toBe(false);
  ensurePathExists(path.join(testDir, 'file.txt'));
  expect(fs.existsSync(testDir)).toBe(true);
}

function test_ensurePathExists002(testDir: string) {
  fs.mkdirSync(testDir, { recursive: true });
  let error;
  try {
    ensurePathExists(path.join(testDir, 'file.txt'));
  } catch (e) {
    error = e;
  }
  expect(error).toBe(undefined);
}
