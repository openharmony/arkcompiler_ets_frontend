/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, softwareP
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import * as ts from 'typescript';
import * as path from 'node:path';

export function getScriptKind(srcFile: ts.SourceFile): ts.ScriptKind {
  const fileName = srcFile.fileName;
  const ext = path.extname(fileName).toLowerCase();
  switch (ext) {
    case ts.Extension.Js:
      return ts.ScriptKind.JS;
    case ts.Extension.Jsx:
      return ts.ScriptKind.JSX;
    case ts.Extension.Ts:
      return ts.ScriptKind.TS;
    case ts.Extension.Tsx:
      return ts.ScriptKind.TSX;
    case ts.Extension.Json:
      return ts.ScriptKind.JSON;
    case ts.Extension.Ets:
      return ts.ScriptKind.ETS;
    default:
      return ts.ScriptKind.Unknown;
  }
}
