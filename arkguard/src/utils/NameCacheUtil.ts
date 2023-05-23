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

import {FileUtils} from './FileUtils';

export const NAME_CACHE_SUFFIX: string = '.cache.json';
export const PROPERTY_CACHE_FILE: string = 'property.cache.json';

export function writeCache(cache: Map<string, string>, destFileName: string): void {
  // convert map to json string
  if (!cache) {
    return;
  }

  const cacheString: string = JSON.stringify(Object.fromEntries(cache));
  FileUtils.writeFile(destFileName, cacheString);
}

export function readCache(filePath: string): Object | undefined {
  // read json string from file
  const cacheString: string = FileUtils.readFile(filePath);
  if (cacheString === undefined) {
    return undefined;
  }

  // get map from json string
  return JSON.parse(cacheString);
}

export function getMapFromJson(jsonObj: Object): Map<string, string> {
  if (jsonObj === undefined) {
    return new Map<string, string>();
  }

  return new Map<string, string>(Object.entries(jsonObj));
}
