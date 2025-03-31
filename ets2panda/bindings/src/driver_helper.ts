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

import { Context, Config } from "./types"
import { global } from "./global"
import { throwError } from "./utils"
import { Es2pandaContextState } from "./generated/Es2pandaEnums"
import { withStringResult } from "./Platform"
import { KBoolean, KPointer } from "./InteropTypes"

export class DriverHelper {
  constructor(filePath: string, cmd: string[]) {
    this._filePath = filePath
    global.filePath = this._filePath
    this._cfg = Config.create(cmd, filePath)
  }
  private _ctx: Context | undefined
  private _cfg: Config
  private _filePath: string

  public createCtx(source: string): KPointer {
    this._ctx = Context.createFromString(source)
    return this._ctx.peer
  }

  public toString(): string {
    return `DriverHelper (filepath = ${this._filePath}, config = ${this._cfg}, context = ${this._ctx})`
  }

  public proceedToState(state: Es2pandaContextState) {
    if (this._ctx === undefined) {
      throwError("Trying to proceed to state while cts is undefined")
    }
    if (state <= global.es2panda._ContextState(this._ctx.peer)) {
      return
    }

    try {
      global.es2panda._ProceedToState(this._ctx.peer, state)
      if (global.es2panda._ContextState(this._ctx.peer) === Es2pandaContextState.ES2PANDA_STATE_ERROR) {
        const errMsg = withStringResult(global.es2panda._ContextErrorMessage(this._ctx.peer))
        if (errMsg === undefined) {
          throwError(`Couldn't get context error msg`)
        } else {
          throwError("Failed proceed to: " + Es2pandaContextState[state] + "\n" + errMsg)
        }
      }
    } catch (e) {
      global.es2panda._DestroyContext(this._ctx.peer)
      throw e
    }
  }

  public finalize() {
    if (this._cfg === undefined) {
      throwError("Call finalize before initialized config")
    }
    if (this._ctx === undefined) {
      throwError("Call finalize before initialized context")
    }
    global.es2panda._DestroyContext(this._ctx.peer)
    global.es2panda._DestroyConfig(this._cfg.peer)
    this._ctx = undefined
    global.destroyCfg()
  }

  public generateTsDecl(declOutPath: string, etsOutPath: string, exportAll: boolean) {
    let exportAll_: KBoolean = exportAll ? 1 : 0
    global.es2panda._GenerateTsDeclarationsFromContext(this._cfg.peer, declOutPath, etsOutPath, exportAll_)
  }
}

export class LspDriverHelper {
  public createCfg(cmd: string[], filePath: string): Config {
    return Config.create(cmd, filePath, true)
  }

  public createCtx(source: string, filePath: string, cfg: Config): Context {
    return Context.lspCreateFromString(source, filePath, cfg)
  }

  public proceedToState(ctx: Context, state: Es2pandaContextState) {
    if (ctx === undefined) {
      throwError("Trying to proceed to state while cts is undefined")
    }
    if (state <= global.es2panda._ContextState(ctx.peer)) {
      return
    }

    try {
      global.es2panda._ProceedToState(ctx.peer, state)
    } catch (e) {
      global.es2panda._DestroyContext(ctx.peer)
      throw e
    }
  }

  public destroyContext(ctx: Context) {
    if (ctx === undefined) {
      return
    }
    global.es2panda._DestroyContext(ctx.peer)
  }

  public destroyConfig(cfg: Config) {
    if (cfg === undefined) {
      return
    }
    global.es2panda._DestroyConfig(cfg.peer)
  }
}
