/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import assert from 'assert'

export type callback<T> = ()=>T;
export type CallbackArray<T extends callback<T>> = ()=>T;
type t = ()=>t;
let a: CallbackArray<()=>t>;
a = ()=>a;
assert(a() === a);

let var1: number = 1;
typeof var1;
type t01 = typeof var1;
let a2:t01 = 1;
assert(a2 === 1);

let c: [string, number, boolean] = ["", 1, false];
assert(c[0] === "");
assert(c[1] === 1);
assert(c[2] === false);


type a = [number, string, ...number[]];

let temp1: number | string = 1;
assert(temp1 === 1);
let temp2: number & (string | number) = 1;
assert(temp2 === 1);
type temp7 = number;
type temp8 = string;
function foo<T>(param: T extends temp7 ? temp7 : temp8) { return param};
assert(foo<number>(1) === 1);

type X2<T> = T extends {a: infer U, b: infer U} ? U : never;
let x: X2<{a:number, b:number}> = 1;
assert(x === 1);

let temp6: (string | number)[] = [1,2];
assert(temp6[0] === 1);
assert(temp6[1] === 2);

interface Person {
  name: string;
  age: number;
};
type PersonKeys = keyof Person;
let b: PersonKeys = "name";
assert(b === "name");


type T1 = {U:number};
let temp5:T1['U'] = 2;
assert(temp5 === 2);

type Foo<T extends any[]> = {
  [P in keyof T]: T[P]
};
let d:Foo<number[]> = [1];
assert(d[0] === 1);

let temp3: "cc" = "cc";
assert(temp3 === "cc");
let temp4: [prop1: string, prop2: number] = ["1",2];
assert(temp4[0] === "1");
assert(temp4[1] === 2);

type T2 = {
  description: string;
  f1(para1: number): boolean;
  (para2: number): number;
};
const temp9: T2 = (para3: number) => para3;
temp9.description = "test";
temp9.f1 = (para4: number) => {
  return para4 > 0 ? true : false;
}
assert(temp9(100) === 100);
assert(temp9.description === "test");
assert(temp9.f1(-100) === false);

type T3 = (para5: number) => number;
const temp10: T3 = (para6: number) => para6;
assert(temp10(200) === 200);