/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

import { User, Person, Fruit, Apple, foo, bar, X, Y } from "./oh_modules/object_literal_constructor"

//Variable Declaration
let user: User = { id: 1 }

let fruit: Fruit = new Fruit("fruit"); // legal

let person: Person = { name: "Furkan", age: "25" }

const base = { title: 'value' };
const y: X = { ...base };

// Call expression
foo({name:" cfe"});
foo(new X("cfe"));  //legal
bar({name:" cfe"});  //legal

//Return statement
function createItem(): X {
    return { title: 'item' };
}

function getClass(): X {
    return new X("cfe"); //legal
}

function createItem2(): Y {
    return { title: 'item' }; //legal
}

// Property Declaration
class Wrapper {
    item: X = { title: 'invalid' };
}

class WrapperLegal {
    item: X = new X("cfe"); //legal
}

// As Expression
const x = { title: 'value' } as X;
const val = new X("cfe") as X; //legal

// Conditional Expression
const condition = true;

const value: X = condition ? { title: 'hello' } : new X("cfe");

const value2: X = condition ? new Fruit("ase") : new X("sea"); //legal

//Binary Expression
let u: X;

u = {
  a: 'assign',
  b: 88
};

u = new Fruit("apple") // legal

//ArrayLiteralExpression
const arr: X[] = [
    { a: 'fail', b: 5 },
    { a: 'bad', b: 6 }
  ];

const arrLegal: X[] = [new X("cfe"), new X("cfe")]; //legal