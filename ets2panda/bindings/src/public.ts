/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

import { global } from "./global"
import { LspDefinitionData, LspDiagsNode } from "./lspNode"
import { unpackString } from "./private"
export class Lsp {
  getDefinitionAtPosition(filename: String, offset: number): LspDefinitionData {
    let ptr = global.es2panda._getDefinitionAtPosition(filename, offset)
    return new LspDefinitionData(ptr)
  }

  getSemanticDiagnostics(filename: String): LspDiagsNode {
    let ptr = global.es2panda._getSemanticDiagnostics(filename)
    return new LspDiagsNode(ptr)
  }

  getCurrentTokenValue(filename: String, offset: number) {
    let ptr = global.es2panda._getCurrentTokenValue(filename, offset)
    return unpackString(ptr)
  }
}
