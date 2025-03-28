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

import { KNativePointer as KPtr } from "./InteropTypes"
import { global } from "./global"
import { throwError } from "./utils"
import { passString, passStringArray, unpackString } from "./private"
import { isNullPtr } from "./Wrapper"

export const arrayOfNullptr = new BigUint64Array([BigInt(0)])

export abstract class ArktsObject {
  protected constructor(peer: KPtr) {
    this.peer = peer
  }

  readonly peer: KPtr
}

export abstract class Node extends ArktsObject {
  protected constructor(peer: KPtr) {
    if (isNullPtr(peer)) {
      throw new Error('trying to create new Node on NULLPTR')
    }
    super(peer)
  }

  public get originalPeer(): KPtr {
    return global.es2panda._AstNodeOriginalNodeConst(global.context, this.peer)
  }

  public set originalPeer(peer: KPtr) {
    global.es2panda._AstNodeSetOriginalNode(global.context, this.peer, peer)
  }

  protected dumpMessage(): string {
    return ``
  }

  public dumpJson(): string {
    return unpackString(global.es2panda._AstNodeDumpJsonConst(global.context, this.peer))
  }

  public dumpSrc(): string {
    return unpackString(global.es2panda._AstNodeDumpEtsSrcConst(global.context, this.peer))
  }
}

export class Config extends ArktsObject {
  readonly path: string
  constructor(peer: KPtr, fpath: string) {
    super(peer)
    // TODO: wait for getter from api
    this.path = fpath
  }

  public toString(): string {
    return `Config (peer = ${this.peer}, path = ${this.path})`
  }

  static create(
    input: string[], fpath: string
  ): Config {
    if (!global.configIsInitialized()) {
      let cfg = global.es2panda._CreateConfig(input.length, passStringArray(input))
      global.config = cfg
      return new Config(
        cfg, fpath
      )
    } else {
      return new Config(global.config, fpath)
    }
  }
}

export class Context extends ArktsObject {
  constructor(peer: KPtr) {
    super(peer)
  }

  public toString(): string {
    return `Context (peer = ${this.peer})`
  }

  static createFromString(
    source: string
  ): Context {
    if (!global.configIsInitialized()) {
      throwError(`Config not initialized`)
    }
    return new Context(
      global.es2panda._CreateContextFromString(
        global.config,
        passString(source),
        passString(global.filePath)
      )
    )
  }
}
