/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

class C {
  firstName: string;
  lastName: string;
  constructor(firstName: string, lastName: string) {
    this.firstName = firstName;
    this.lastName = lastName;
  }

  fullName(): string {
    return this.firstName + " " + this.lastName;
  }
}

function foo(): void {
  const person1 = new C("Arthur", "Clarke");
  const person2 = new C("Ray", "Bradbury");

  const fullName = person1.fullName.apply(person2);

  const f = person2.fullName.bind(person1);
  f();

  bar(person1);
}

function bar(c: C): string {
  const person = new C("Stanislaw", "Lem");
  return c.fullName.call(person);
}

const person = {
  fn: "Ben",
  f1: function () {
    return this.fn; // here `this` is the current obj
  },
  f2: function (): string {
    return this.fn; // here `this` is the current obj
  },
  f3: () => {
    return this.fo; // here `this` is `globalThis`
  },
  f4: (): string => {
    return this.fo; // here `this` is `globalThis`
  },
};

const person1 = {
  fn: "Mary",
};

console.log(person.f1.apply(person1));
console.log(person.f2.apply(person1));
console.log(person.f3.apply(person1));
console.log(person.f4.apply(person1));

foo.apply(undefined);
