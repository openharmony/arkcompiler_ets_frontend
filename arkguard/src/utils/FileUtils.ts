/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

import {existsSync, readFileSync, writeFileSync} from 'fs';
import {readJsonSync} from 'fs-extra';
import type {IOptions} from '../configs/IOptions';

export class FileUtils {
  /**
   * Read file and return content
   *
   * @param filePath file path
   */
  public static readFile(filePath: string): string | undefined {
    if (!existsSync(filePath)) {
      console.error(`File <${this.getFileName(filePath)} is not found.>`);
      return undefined;
    }
    return readFileSync(filePath, 'utf-8');
  }

  /**
   * Read file and convert to json object.
   *
   * @param filePath file path
   */
  public static readFileAsJson(filePath: string): IOptions | undefined {
    if (!existsSync(filePath)) {
      console.error(`File <${this.getFileName(filePath)} is not found.>`);
      return undefined;
    }

    try {
      return readJsonSync(filePath);
    } catch (e) {
      console.error('json file read error: ' + filePath);
      return undefined;
    }
  }

  /**
   * Get File Name
   *
   * @param filePath file path
   */
  public static getFileName(filePath: string): string | undefined {
    if (!filePath) {
      return undefined;
    }

    const lastSepIndex: number = filePath.lastIndexOf('/');
    if (lastSepIndex >= 0) {
      return filePath.slice(lastSepIndex + 1);
    }

    return filePath.slice(filePath.lastIndexOf('\\') + 1);
  }

  /**
   * Get suffix of a file.
   *
   * @param filePath file path
   */
  public static getFileExtension(filePath: string): string | undefined {
    if (!filePath || !filePath.includes('.')) {
      return undefined;
    }

    // get file name
    let fileName: string = this.getFileName(filePath);
    if (!fileName.includes('.')) {
      return undefined;
    }

    return fileName.slice(fileName.lastIndexOf('.') + 1);
  }

  public static writeFile(filePath: string, content: string): void {
    writeFileSync(filePath, content);
  }

  /**
   * get prefix of directory
   * @param dirPath
   */
  public static getPrefix(dirPath: string): string | undefined {
    if (!dirPath || (!dirPath.includes('/') && !dirPath.includes('\\'))) {
      return undefined;
    }

    const sepIndex: number = dirPath.lastIndexOf('/');
    if (sepIndex >= 0) {
      return dirPath.slice(0, sepIndex + 1);
    }

    return dirPath.slice(0, dirPath.lastIndexOf('\\') + 1);
  }

  public static getPathWithoutPrefix(filePath: string, prefix: string): string | undefined {
    if (!filePath.startsWith(prefix)) {
      return filePath;
    }

    return filePath.slice(prefix.length);
  }
}
