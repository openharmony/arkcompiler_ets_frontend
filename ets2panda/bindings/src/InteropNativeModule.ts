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

import { KNativePointer as KPtr, KInt } from "./InteropTypes"
import { loadNativeModuleLibrary, registerNativeModuleLibraryName } from "./loadLibraries"
import { throwError } from "./utils"

export class InteropNativeModule {
  _StringLength(ptr: KPtr): KInt {
    throw new Error("Not implemented")
  }
  _StringData(ptr: KPtr, buffer: KPtr, length: KInt): void {
    throw new Error("Not implemented")
  }
  _GetStringFinalizer(): KPtr {
    throw new Error("Not implemented")
  }
  _InvokeFinalizer(ptr: KPtr, finalizer: KPtr): void {
    throw new Error("Not implemented")
  }
  _GetPtrVectorSize(ptr: KPtr): KInt {
    throw new Error("Not implemented")
  }
  _GetPtrVectorElement(ptr: KPtr, index: KInt): KPtr {
    throw new Error("Not implemented")
  }
}

export function initInterop(): InteropNativeModule {
  let libPath = process.env.BINDINGS_PATH
  if (libPath == undefined) {
    throwError("Cannot find env variable $BINDINGS_PATH")
  }
  // registerNativeModuleLibraryName("NativeModule", "/home/nojpg/projects/panda/runtime_core/static_core/build/lib/bindings/ts_bindings.node")
  registerNativeModuleLibraryName("NativeModule", libPath + "/ts_bindings.node")
  // registerNativeModuleLibraryName("InteropNativeModule", "/home/nojpg/projects/panda/runtime_core/static_core/build/lib/bindings/ts_bindings.node")
  const instance = new InteropNativeModule()
  loadNativeModuleLibrary("InteropNativeModule", instance)
  return instance
}
