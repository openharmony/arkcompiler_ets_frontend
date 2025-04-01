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

import { KInt, KNativePointer, KUInt } from "./InteropTypes"
import { unpackString, VariantTypes } from "./private"
import { throwError } from "./utils"
import { isNullPtr } from "./Wrapper"
import { global } from "./global"
import { NativePtrDecoder } from "./Platform"

export abstract class LspNode {
  readonly peer: KNativePointer

  protected constructor(peer: KNativePointer) {
    if (isNullPtr(peer)) {
      throwError("nullptr from peer in lspnode constuctor")
    }
    this.peer = peer
  }
}

export class LspPosition extends LspNode {
  readonly line: number
  readonly character: number
  constructor(peer: KNativePointer) {
    super(peer)
    this.line = global.es2panda._getPosLine(peer)
    this.character = global.es2panda._getPosChar(peer)
  }
}

export class LspRange extends LspNode {
  readonly start: LspPosition
  readonly end: LspPosition
  constructor(peer: KNativePointer) {
    super(peer)
    this.start = new LspPosition(global.es2panda._getRangeStart(peer))
    this.end = new LspPosition(global.es2panda._getRangeEnd(peer))
  }
}

export enum LspDiagSeverity {
  Error = 1,
  Warning = 2,
  Information = 3,
  Hint = 4,
}

export enum LspDiagTag {
  Unnecessary = 1,
  Deprecated = 2,
}

export class LspLocation extends LspNode {
  constructor(peer: KNativePointer) {
    super(peer)
    this.uri = unpackString(global.es2panda._getLocUri(peer))
    this.range = new LspRange(global.es2panda._getLocRange(peer))
  }
  readonly uri: string
  readonly range: LspRange
}

export class LspRelatedInfo extends LspNode {
  constructor(peer: KNativePointer) {
    super(peer)
    this.message = unpackString(global.es2panda._getRelatedInfoMsg(peer))
    this.location = new LspLocation(global.es2panda._getRelatedInfoLoc(peer))
  }
  readonly message: string
  readonly location: LspLocation
}

export class LspCodeDescription extends LspNode {
  constructor(peer: KNativePointer) {
    super(peer)
    this.href = unpackString(global.es2panda._getCodeDescriptionHref(peer))
  }
  readonly href: string
}

export class LspDiagnosticNode extends LspNode {
  constructor(peer: KNativePointer) {
    super(peer)
    this.message = unpackString(global.es2panda._getDiagMsg(peer))
    this.source = unpackString(global.es2panda._getDiagSource(peer))
    this.range = new LspRange(global.es2panda._getDiagRange(peer))
    this.tags = new NativePtrDecoder()
      .decode(global.es2panda._getDiagTags(peer))
      .map((elPeer: KNativePointer) => elPeer as KInt)
    this.relatedInfo = new NativePtrDecoder()
      .decode(global.es2panda._getDiagRelatedInfo(peer))
      .map((elPeer: KNativePointer) => new LspRelatedInfo(elPeer))
    let codeVarPtr = global.es2panda._getDiagCode(peer)
    if (global.interop._getTypeOfVariant(codeVarPtr) == VariantTypes.VARIANT_INT) {
      this.code = global.interop._getIntFromVariant(codeVarPtr)
    } else {
      this.code = unpackString(global.interop._getStringFromVariant(codeVarPtr))
    }
    let dataPtr = global.es2panda._getDiagData(peer)
    if (global.interop._getTypeOfVariant(dataPtr) == VariantTypes.VARIANT_INT) {
      this.data = global.interop._getIntFromVariant(dataPtr)
    } else {
      this.data = unpackString(global.interop._getStringFromVariant(dataPtr))
    }
    this.severity = global.es2panda._getDiagSeverity(peer)
    this.codeDescription = new LspCodeDescription(global.es2panda._getDiagCodeDescription(peer))
  }
  readonly source: String
  readonly message: String
  readonly range: LspRange
  readonly codeDescription: LspCodeDescription
  readonly severity: LspDiagSeverity
  readonly tags: LspDiagTag[]
  readonly relatedInfo: LspRelatedInfo[]
  readonly code: number | String
  readonly data: number | string
}

export class LspDiagsNode extends LspNode {
  constructor(peer: KNativePointer) {
    super(peer)
    this.diagnostics = new NativePtrDecoder()
      .decode(global.es2panda._getDiags(this.peer))
      .map((elPeer: KNativePointer) => {
        return new LspDiagnosticNode(elPeer)
      })
  }
  readonly diagnostics: LspDiagnosticNode[]
}

export class LspDefinitionData extends LspNode {
  constructor(peer: KNativePointer) {
    super(peer)
    this.fileName = unpackString(global.es2panda._getFileNameFromDef(peer))
    this.start = global.es2panda._getStartFromDef(peer)
    this.length = global.es2panda._getLengthFromDef(peer)
  }
  readonly fileName: String
  readonly start: KInt
  readonly length: KInt
}
