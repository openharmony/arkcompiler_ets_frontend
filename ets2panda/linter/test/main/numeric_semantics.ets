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