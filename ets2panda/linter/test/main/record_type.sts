/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

function recordType(): void {
  class Person {
    name: string = ""
    age: number = 0
    location: string = ""
  }
    
  let persons : Record<string, Person> = {
    "Alice": { name: "Alice", age: 32, location: "Shanghai" },
    "Bob": { name: "Bob", age: 48, location: "New York" }
  };
  console.log(persons["Bob"].age)
  console.log(persons["Rob"].age) // Runtime exception

  type OptionalPerson = Person | undefined
  let persons2 : Record<string, OptionalPerson> = {
    "Alice": { name: "Alice", age: 32, location: "Shanghai" },
    "Bob": { name: "Bob", age: 48, location: "New York" }
  };
  console.log(persons2["Bob"]!.age)
  if (persons2["Rob"]) { // Explicit value check, no runtime exception
    console.log(persons2["Rob"].age)
  }
 
  let persons3 : Record<string, Person | undefined> = {
    "Alice": { name: "Alice", age: 32, location: "Shanghai" },
    "Bob": { name: "Bob", age: 48, location: "New York" }
  };
  console.log(persons3["Bob"]!.age)
  if (persons3["Rob"]) { // Explicit value check, no runtime exception
    console.log(persons3["Rob"].age)
  }

  type R1 = Record<number, string>; // ok
  type R2 = Record<1 | 2, string>; // ok
  type R3 = Record<"salary" | "bonus", number>; // ok

  type Keys = 'key1' | 'key2' | 'key3'
  let x: Record<Keys, number> = {
    'key1': 1,
    'key2': 2,
    'key3': 4,
  };
  console.log(x['key2']) // prints 2
  x['key2'] = 8
  console.log(x['key2']) // prints 8
}


// Initializing Record<K, T>
let m1: Record<string, number | undefined> = { // OK
  'a': 33,
  'b': 44
};

class Person {
  name: string = ""
  age: number = 0
  location: string = ""
}

type OptionalPerson = Person | undefined;
let persons : Record<string, OptionalPerson> = { // OK
  "Alice": { name: "Alice", age: 32, location: "Shanghai" },
  "Bob": { name: "Bob", age: 48, location: "New York" }
};
let persons2 : Record<string, Person | undefined> = { // OK
  "Alice": { name: "Alice", age: 32, location: "Shanghai" },
  "Bob": { name: "Bob", age: 48, location: "New York" }
};

// issue 13026: Record with type alias
type REC = Record<string | number, string>;
let rec: REC = { // OK, Record is used through type alias
  'name': 'john',
  'address': '124213',
  'birthday': '2020-03-10',
  23:'xx'
};

rec = { // NOT OK, key must be either string or number literal
  name: 'john',
  address: '124213',
  birthday: '2020-03-10',
  23:'xx'
}

// #14360 - Record in a union type
class RecUnion {
  v: Record<string, string> | null = null;
}
let recU: RecUnion = {
  v: {
    'a': 'v'
  }
};

interface RecUnion2 {
  param: Record<string, string | number | undefined | null>;
  extra?: Record<string, string | number | undefined | null>;
  value: Record<string, string | number> | string;
}
let recU2: RecUnion2 = {
  param: {
    'aa': 111
  },
  extra: {
    'bbb': 222
  },
  value: {
    'bbb': 222
  }
};

class RecUnion3 {
  extra: Record<string, number> | string = '';
  param?: Record<string, number> | string = '';
}
let recU3: RecUnion3 = {
  extra: {
    'bbb': 222
  },
  param: {
    'bbb': 222
  }
};