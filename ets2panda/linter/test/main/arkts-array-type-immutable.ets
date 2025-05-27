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

let a: number[] = [1]
let b: (number | string)[] = a // error

let a1: (number | string)[] = [1]
let b1: (number | string)[] = a1 // ok

let b2: (number | string)[];
b2 = a // error

class A {
    a: (number | string)[] = [1];
}

let aA: A = new A();
aA.a = a; // error

let a3: (number | string)[] = new Array<number>(1, 2); // error

function test(a: number[]): void {
  let b: (number | string)[] = [1];
  b = a; // error
}