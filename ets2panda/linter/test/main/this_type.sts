/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

interface Adder {
  addFoo(): this;

  addBar(): this;

  addGreeting(name: string): this;
}

class StringAdder implements Adder {
  value = "";

  getValue(): string {
    return this.value;
  }

  addFoo(): this {
    this.value += "foo";
    return this;
  }

  addBar(): this {
    this.value += "bar";
    return this;
  }

  addGreeting(name: string): this {
    this.value += `Hi ${name}`;
    return this;
  }
}
const stringAdder: StringAdder = new StringAdder();

const str = stringAdder.addFoo().addBar().addGreeting("Jane").getValue();

console.log(str);

class C {
  m(c: this): void {
    console.log(c);
  }
}

class HH {
  f = () => {
    this;
  };
  ff() {
    this;
    let fff = () => {
      this;
    };
    fff();
  }
  ffff(): void {
    this;
  }
  static fffff() {
    this;
  }
}

let g = () => {
  this;
};
let gg = function () {
  this;
};
function ggg() {
  this;
}

class HHH {
  static {
    this;
  }
}
