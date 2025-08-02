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

// Positive (should be flagged)
let a: A;                     // ❌ VariableMissingInitializer
let b: number[];              // ❌ VariableMissingInitializer
let c: A<ESValue>;            // ❌ VariableMissingInitializer
const x: X;                   // ❌ VariableMissingInitializer

// Negative (should NOT be flagged)
// 1) Initialized declarations
let d: D = new D();              // ✅ OK
const y1: string = "hello";      // ✅ OK

// 2) Function‐typed declarations are skipped
let add: (a: number, b: number) => number;    // ✅ OK
let handler: (e: Event) => void;              // ✅ OK

// 3) Explicit void‐typed declarations are skipped
let v: void;                  // ✅ OK
const v2: void;               // ✅ OK

// 4) For…of and For…in loop bindings
for (let item of items) {     // ✅ OK
  console.log(item);
}

for (let key in record) {     // ✅ OK
  console.log(key);
}

// 5) Function declarations / expressions
function foo() {              // ✅ OK
  return 42;
}

let bar = function() {        // ✅ OK
  return "hi";
};

let baz = () => {             // ✅ OK
  return true;
};

// 6) Destructuring with initializer
let { x, y } = point;         // ✅ OK
