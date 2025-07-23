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
import { DECL_ETS_SUFFIX, LANGUAGE_VERSION } from './pre_define';
import { BuildConfig } from './types';

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

export function isSubPathOf(targetPath: string, parentDir: string): boolean {
  const resolvedParent = toUnixPath(path.resolve(parentDir));
  const resolvedTarget = toUnixPath(path.resolve(targetPath));
  return resolvedTarget === resolvedParent || resolvedTarget.startsWith(resolvedParent + '/');
}

export function createFileIfNotExists(filePath: string, content: string): boolean {
  try {
    const normalizedPath = path.normalize(filePath);
    if (fs.existsSync(normalizedPath)) {
      return false;
    }

    const dir = path.dirname(normalizedPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    fs.writeFileSync(normalizedPath, content, { encoding: 'utf-8' });
    return true;
  } catch (error) {
    return false;
  }
}

export function isHybrid(buildConfig: BuildConfig): boolean {
  return buildConfig.dependentModuleList.some(
    module => module.language === LANGUAGE_VERSION.ARKTS_1_1 || 
              module.language === LANGUAGE_VERSION.ARKTS_HYBRID
  );
}
