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

interface Author {
  firstName: string;
  lastName: string;
  anotherName: Function;
  asyncName: Function;
}

class C {
  firstName: string;
  lastName: string;
  constructor(firstName: string, lastName: string) {
    this.firstName = firstName;
    this.lastName = lastName;
    this.fullName = this.fullName.bind(this);
    this.asyncFullName = this.asyncFullName.bind(this);
   }

   author(): Author {
       let author: Author = {
         firstName: this.firstName,
         lastName: this.lastName,
         anotherName: this.fullName.bind(this),
         asyncName: this.asyncFullName.bind(this)
       }
       return author
   }

  fullName(): string {
    return this.firstName + " " + this.lastName;
  }

  async asyncFullName(): Promise<string> {
    return Promise<string>(fullName());
  }

  sayHello(greet: string) {
    console.log(greet, this.fullName());
  }

  async asyncSayHello(greet: string) {
    const afn = await this.asyncFullName();
    console.log(greet, afn);
  }
}

async function asyncFoo(): Promise<void> {
  const person1 = new C("Arthur", "Clarke");
  const person2 = new C("Ray", "Bradbury");

  await person1.asyncFullName();
  const afn = await person1.asyncFullName();

  const afn2 = await person1.asyncFullName.apply(person2);

  const f = person2.asyncFullName.bind(person1);
  await f();

  await asyncBar(person1);

  const ash1: Function = person1.asyncSayHello.bind(person1, "Hello");
  await ash1()

  const ash2: Function = person1.asyncSayHello.bind(person1);
  await ash2("Hello")

  await person1.asyncSayHello.apply(person2, "Hello");
  await person1.asyncSayHello.call(person2, "Hello")
}

async function asyncBar(c: C): Promise<string> {
  const person = new C("Stanislaw", "Lem");
  return await c.asyncFullName.call(person);
}

function foo(): void {
  const person1 = new C("Arthur", "Clarke");
  const person2 = new C("Ray", "Bradbury");

  const fullName = person1.fullName.apply(person2);

  const f = person2.fullName.bind(person1);
  f();

  bar(person1);

  const sh1: Function = person1.sayHello.bind(person1, "Hello");
  sh1()

  const sh2: Function = person1.sayHello.bind(person1);
  sh2("Hello")

  person1.sayHello.apply(person2, "Hello");
  person1.sayHello.call(person2, "Hello")
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
