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

import { throwError } from "./utils"
import { KNativePointer, nullptr } from "./InteropTypes"
import { withString, withStringArray } from "./arrays"
import { NativePtrDecoder, withStringResult } from "./Platform"
import { isNullPtr } from "./Wrapper"

export function lspData(peer: KNativePointer): LspNode {
  // for example we create for diagnostics only, example commented above
  // TODO add other nodes with checking, type we know by request noneed extra matchin call with maps
  // so dispatch will be easier
  return new LspDiagsNode(peer)
}

export abstract class LspNode {
  readonly peer: KNativePointer

  protected constructor(peer: KNativePointer) {
    if (isNullPtr(peer)) {
      throwError("nullptr from peer in lspnode constuctor")
    }
    this.peer = peer
  }
}

export class LspDiagnosticNode extends LspNode {
  //TODO fill all fields like range severity source message etc...
  constructor(peer: KNativePointer) {
    super(peer)
  }
}
export class LspDiagsNode extends LspNode {
  constructor(peer: KNativePointer) {
    super(peer)
    // TODO Implement getDiagnostics with c-api to return vector and unpack it lately
    // this.diagnostics = unpackNodeArray(global.generatedEs2panda._getDiagnostics(global.context, this.peer))
  }
  // TODO remove undefined when implemented 
  diagnostics: LspDiagnosticNode[] | undefined
}


export function unpackNonNullableNode<T extends LspNode>(peer: KNativePointer): T {
  if (peer === nullptr) {
    throwError('peer is NULLPTR (maybe you should use unpackNode)')
  }
  return lspData(peer) as T
  // return classByPeer(peer) as T
}

export function unpackNode<T extends LspNode>(peer: KNativePointer): T | undefined {
  if (peer === nullptr) {
    return undefined
  }
  return lspData(peer) as T
  // return classByPeer(peer) as T
}

// meaning unpackNonNullableNodeArray
export function unpackNodeArray<T extends LspNode>(nodesPtr: KNativePointer): readonly T[] {
  if (nodesPtr === nullptr) {
    throwError('nodesPtr is NULLPTR (maybe you should use unpackNodeArray)')
  }
  return (new NativePtrDecoder())
    .decode(nodesPtr)
    .map((peer: KNativePointer) => unpackNonNullableNode(peer))
}

export function unpackString(peer: KNativePointer): string {
  return withStringResult(peer) ?? throwError(`failed to unpack (peer shouldn't be NULLPTR)`)
}

export function passString(str: string | undefined): string {
  if (str === undefined) {
    return ""
  }
  return withString(str, (it: string) => it)
}

export function passStringArray(strings: string[]): Uint8Array {
  return withStringArray(strings)
}
