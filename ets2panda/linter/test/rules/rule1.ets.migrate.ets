/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

let x = { "name": 1, 2: 3 }

console.log(x["name"])
console.log(x[2])

class X {
    public name: number = 0
}
interface GeneratedObjectLiteralInterface_1 {
    name: number;
}
let y: GeneratedObjectLiteralInterface_1 = {name: 1}
console.log(x.name)

let z = [1, 2, 3]
console.log(y[2])

enum S1 {
  s1 = "qwqwq",
}

enum S2 {
  s2 = 123,
}

interface A1 {
  [S1.s1]: string;
}

interface A2 {
  [S2.s2]: string;
}

const a1: A1 = {
  [S1.s1]: "fld1",
};

const a2: A2 = {
  [S2.s2]: "fld2",
};

S1["s1"];
S2["s2"];
