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

// TypeScript: treats 'n' as having type number
// ArkTS: treats 'n' as having type int to reach max code performance
let a = 1;

a = 1; // OK
a = 1.5; // CTE in ArkTS: Type 'double' can't be assigned to type 'int'

a += 1; // OK
a += 1.5; // ArkTS: Result is integer value

console.log(a + 1); // OK
console.log(a - 0.5); // OK
console.log(a / 2); // ArkTS: integer division is used, result is integer value
console.log(a / 2.5); // OK
console.log(2 / a); // ArkTS: integer division is used, result is integer value
console.log(2.5 / a); // OK

let b: number = 1;
a = b; // CTE in ArkTS: Type 'double' can't be assigned to type 'int'
a += b; // ArkTS: Result is integer value
console.log(a + b); // OK
console.log(a / b); // OK

let c = 1.5;
a = c; // CTE in ArkTS: Type 'double' can't be assigned to type 'int'
a += c; // ArkTS: Result is integer value
console.log(a + c); // OK
console.log(a / c); // OK

let d = 2;
a = d; // OK
a += d; // OK
console.log(a + d); // OK
console.log(a / d); // ArkTS: integer division is used, result is integer value

let n = 2;

let f: number = 1

let g = [1, 2, 3]

let x!: number

let t8 = Infinity

let t9 = -Infinity;

let t10 = NaN;

let t11 = Number.MAX_VALUE;

let t12 = Number.MIN_VALUE;

let o:number = 123;

const oo:number = 123;

let o2 = o; 

let o3 = oo; 

class A{
   a = 1;
   constructor() {
  }
}

let t2 = +123;

let t3 = -234;

let num = Math.floor(4.8); // num 可能是 int

let value = parseInt("42"); // value 可能是 int


function multiply(x = 2, y = 3) { 
 return x * y;
}

function divide(x: number, y: number) {
  return x / y;
}

function identity<T>(value: T): T {
  return value;
}
identity(42);

let an_array = [1,2,3]

let g = an_array[]
