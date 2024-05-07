/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

class A {
  prop: string = 'aaa';

  static prop: number = 1;
  static getProp(): number {
    return A.prop;
  }

  constructor() {
    "use sendable"
  }

}

class B {
  prop: A = new A();

  constructor() {
    "use sendable"
  }

  setPropOfA() {
    A.prop = 2;
  }

  getPropofA() {
    return A.getProp();
  }
}

let b = new B();
b.setPropOfA();

print(b.getPropofA());
print(b.prop.prop);
