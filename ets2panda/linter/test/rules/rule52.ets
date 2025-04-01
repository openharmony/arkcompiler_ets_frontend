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

// bad

class C1 {
  foo1() {
    console.log("foo");
  }
}

function bar1() {
  console.log("bar");
}

let c11 = new C1();
let c12 = new C1();
c12.foo1 = bar;

c11.foo1(); // foo
c12.foo1(); // bar

// good

class C {
  foo() {
    console.log("foo");
  }
}

class Derived extends C {
  foo() {
    console.log("Extra");
    super.foo();
  }
}

function bar() {
  console.log("bar");
}

let c1 = new C();
let c2 = new C();
c1.foo(); // foo
c2.foo(); // foo

let c3 = new Derived();
c3.foo(); // Extra foo
