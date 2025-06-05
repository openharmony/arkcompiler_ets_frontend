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

enum TEST {
  A,
  B,
  C
}
const arr = ['a', 'b', 'c'];

const val = TEST[1]; //error
const value: number = TEST.A;
const arrVal = arr[1];
let a = 1;
let b = 2.3;
let c = "str";
let d3 = TEST[TEST.A];
let d4 = TEST[a]; //error
let d5 = TEST[b]; //error
let d2 = TEST['A']; //error
enum E { A, B, C }
console.log(E[E.A]);
function foo(e: E) {
  console.log(E[e]);
}
foo(E.B);
console.log(E[2 as E]);
enum Color { Red, Green = 10, Blue }
enum E1 { One = 1, one = 1, oNe = 1 }
console.log(E1[1 as E1])
let c1: Color = Color.Green;
console.log(c1.toString())
console.log(Color[c1]);
enum G {
  A = 1,
  B = 2
}
console.log(G[G.A]);