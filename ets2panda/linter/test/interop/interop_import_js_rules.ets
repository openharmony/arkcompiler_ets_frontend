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
'use static';

import { foo } from "./interop_import_js_rules_js"
import { ff1, ff2 } from "./interop_import_js_rules_js"

import { A } from "./interop_import_js_rules_js"
import { C } from "./interop_import_js_rules_js"

import { ff3 } from "./interop_import_js_rules_js"

import { ff4 } from "./interop_import_js_rules_js"

import { handle } from "./interop_import_js_rules_js"

import { expand } from "./interop_import_js_rules_js"
import { orange } from "./interop_import_js_rules_js"

if (foo.isGood) {}

if (ff1.f1 > 18) {
  console.log("adult");
}

class B extends A {}
let b = new B()
let c = new B()

class E extends C {} // no autofix+error, handled in different pr

try {
  ff4()
} catch (e) {
  e as number  // 123
}

let arr = ff3.arr
let len = arr.length as number
for (let i = 0; i < len; ++i) {
  let x = arr[i]
  arr[i] = 0
}

interface Person {
  name: string
}

function foo2(p: Person) {}
let lambda = (p: Person) => {}

handle(foo2)
handle(lambda)

class X{a = 1; b= 2; c= 3}
expand(new X()) // ERROR expand-static

class Y {
  str: string = 'str';
  bool: boolean = false;
}

let testY: Y = {
  str: "hello",
  bool: false,
}

expand(testY);
expand({x: '1', y: "hello", z: false});

let flag = false;
if (orange.isVegetable1 === 123) {
flag = true
}

for (let element of arr) {
  if (element == 8) {
    console.log("hi");
  }
}
