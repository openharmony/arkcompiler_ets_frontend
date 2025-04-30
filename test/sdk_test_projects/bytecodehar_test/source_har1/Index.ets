/**
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

import {bchar1Test} from "bytecode_har"
import {bytecodeHar1Test} from "bytecode_har1"
import { promptAction } from "@kit.ArkUI";

export { MainPage } from './src/main/ets/components/MainPage'
export function sourceHarDispatchbcHarTest() {
  bchar1Test();
  import ("bytecode_har").then((obj :ESObject)=>{
    console.log("sourcehar1 dynamic import bytecodehar")
    promptAction.showToast({
      message: "sourcehar1 dynamic import bytecodehar",
      duration: 2000
    });
    obj.bchar1Test();
  })

  bytecodeHar1Test();
  import ("bytecode_har1").then((obj :ESObject)=>{
    console.log("dynamic import bytecodehar1")
    promptAction.showToast({
      message: "dynamic import bytecodehar1",
      duration: 2000
    });
    obj.bytecodeHar1Test();
  })
}