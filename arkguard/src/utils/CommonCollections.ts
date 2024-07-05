/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

// This records the collections related to property obfuscation.
export namespace PropCollections {
  // global mangled properties table used by all files in a project
  export let globalMangledTable: Map<string, string> = new Map();
  // used for property cache
  export let historyMangledTable: Map<string, string> = undefined;
  // the white list of property
  export let reservedProperties: Set<string> = new Set();
  export let universalReservedProperties: RegExp[] = [];
  // saved generated property name
  export let newlyOccupiedMangledProps: Set<string> = new Set();
  export let mangledPropsInNameCache: Set<string> = new Set();

  // When the module is compiled, call this function to clear the collections associated with property obfuscation.
  export function clearPropsCollections(): void {
    globalMangledTable.clear();
    historyMangledTable?.clear();
    reservedProperties.clear();
    universalReservedProperties = [];
    newlyOccupiedMangledProps.clear();
    mangledPropsInNameCache.clear();
  }
}