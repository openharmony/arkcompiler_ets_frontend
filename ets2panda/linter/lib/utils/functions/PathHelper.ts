/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import * as npath from 'node:path';
import type * as ts from 'typescript';

export function pathContainsDirectory(path: string, dir: string): boolean {
  for (const pathDir of npath.dirname(path).split(npath.sep)) {
    if (pathDir === dir) {
      return true;
    }
  }
  return false;
}

const srcFilePathComponents = new Map<ts.SourceFile, string[]>();

export function srcFilePathContainsDirectory(srcFile: ts.SourceFile, dir: string): boolean {
  let pathComps = srcFilePathComponents.get(srcFile);
  if (!pathComps) {
    pathComps = npath.dirname(npath.normalize(srcFile.fileName)).split(npath.sep);
    srcFilePathComponents.set(srcFile, pathComps);
  }
  for (const subdir of pathComps) {
    if (subdir === dir) {
      return true;
    }
  }
  return false;
}
