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

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import {
  ARKTS_MODULE_NAME,
  DECL_ETS_SUFFIX,
  NATIVE_MODULE,
  sdkConfigPrefix
} from './pre_define';
import {
  Logger,
  LogData,
  LogDataFactory
} from './logger';
import { ErrorCode } from './error_code';

const WINDOWS: string = 'Windows_NT';
const LINUX: string = 'Linux';
const MAC: string = 'Darwin';

export function isWindows(): boolean {
  return os.type() === WINDOWS;
}

export function isLinux(): boolean {
  return os.type() === LINUX;
}

export function isMac(): boolean {
  return os.type() === MAC;
}

export function changeFileExtension(file: string, targetExt: string, originExt = ''): string {
  let currentExt = originExt.length === 0 ? path.extname(file) : originExt;
  let fileWithoutExt = file.substring(0, file.lastIndexOf(currentExt));
  return fileWithoutExt + targetExt;
}

export function changeDeclgenFileExtension(file: string, targetExt: string): string {
  if (file.endsWith(DECL_ETS_SUFFIX)) {
      return changeFileExtension(file, targetExt, DECL_ETS_SUFFIX);
  }
  return changeFileExtension(file, targetExt);
}

export function ensurePathExists(filePath: string): void {
  try {
    const dirPath: string = path.dirname(filePath);
    if (!fs.existsSync(dirPath)) {
      fs.mkdirSync(dirPath, { recursive: true });
    }
  } catch (error) {
    if (error instanceof Error) {
      console.error(`Error: ${error.message}`);
    }
  }
}

export function getFileHash(filePath: string): string {
  const content = fs.readFileSync(filePath, 'utf8');
  return crypto.createHash('sha256').update(content).digest('hex');
}

export function toUnixPath(path: string): string {
  return path.replace(/\\/g, '/');
}

export function readFirstLineSync(filePath: string): string | null {

  const fd = fs.openSync(filePath, 'r');
  const buffer = Buffer.alloc(256);
  const bytesRead = fs.readSync(fd, buffer, 0, buffer.length, 0);
  fs.closeSync(fd);

  const content = buffer.toString('utf-8', 0, bytesRead);
  const firstLine = content.split(/\r?\n/, 1)[0].trim();

  return firstLine;
}

export function safeRealpath(path: string, logger: Logger): string {
  try {
    return fs.realpathSync(path);
  } catch(error) {
    const msg = error instanceof Error ? error.message : String(error);
    const logData: LogData = LogDataFactory.newInstance(
      ErrorCode.BUILDSYSTEM_PATH_RESOLVE_FAIL,
      `Error resolving path "${path}".`,
      msg
    );
    logger.printError(logData);
    throw logData;
  }
}

export function getInteropFilePathByApi(apiName: string, interopSDKPath: Set<string>): string {
  for (const sdkPath of interopSDKPath) {
    const modulePath = path.resolve(sdkPath, apiName + DECL_ETS_SUFFIX);
    if (fs.existsSync(modulePath)) {
      return modulePath;
    }
  }
  return '';
}

/**
 * Issue:26513
 * todo read config from external instead of prodcue
 */
export function getOhmurlByApi(api: string): string {
  const REG_SYSTEM_MODULE: RegExp = new RegExp(`@(${sdkConfigPrefix})\\.(\\S+)`);

  if (REG_SYSTEM_MODULE.test(api.trim())) {
    return api.replace(REG_SYSTEM_MODULE, (_, moduleType, systemKey) => {
      const systemModule: string = `${moduleType}.${systemKey}`;
      if (NATIVE_MODULE.has(systemModule)) {
        return `@native:${systemModule}`;
      } else if (moduleType === ARKTS_MODULE_NAME) {
        // @arkts.xxx -> @ohos:arkts.xxx
        return `@ohos:${systemModule}`;
      } else {
        return `@ohos:${systemKey}`;
      };
    });
  }
  return '';
}

export function isSubPathOf(targetPath: string, parentDir: string): boolean {
  const resolvedParent = toUnixPath(path.resolve(parentDir));
  const resolvedTarget = toUnixPath(path.resolve(targetPath));
  return resolvedTarget === resolvedParent || resolvedTarget.startsWith(resolvedParent + '/');
}
