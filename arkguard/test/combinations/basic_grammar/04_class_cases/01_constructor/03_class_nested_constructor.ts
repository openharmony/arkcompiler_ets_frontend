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
let a1 = 1;
class A6 {
  constructor(public p001: number, public p002: string) {
    p001 = p001 + 1;
    class A7 {
      constructor(public p001: number, public p003: string) {
        p001 = p001 + 2;
        p002 = p002 + "2";
        p003 = "4";
        this.p001 = p001 + 1;
      }
    }
    let insA7 = new A7(1,"3");
    assert(insA7.p001 === 4);
    assert(insA7.p003 === "3");
    this.p001 = p001;
    this.p002 = p002;
  }
}

let insA6 = new A6(1,"2");
assert(insA6.p001 === 2);
assert(insA6.p002 === "22");
assert(a1 === 1);