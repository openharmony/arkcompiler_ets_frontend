/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the License);
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

import assert from "assert";

interface I6 {
  prop_i6: number;
  method_i6(para: number): number;
}
let cons1 = class C7 implements I6 {
  prop_i6: number = 7;
  method_i6(para: number): number {
    return para * 2 * this.prop_i6;
  }
}
let insC7 = new cons1();
assert(insC7.prop_i6 === 7);
assert(insC7.method_i6(2) === 28);