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
'use static'

class A {
  constructor(a: number) {
  }
}

class B {
  constructor() {
  }
}

class C extends A {} // ERROR

class D extends A { // ERROR super is not called
  constructor(a: number) {}
}

class E extends A { // NO ERROR constructor is called
  constructor(a: number) {
    super(a);
  }
}

class F extends B {} // NO ERROR
