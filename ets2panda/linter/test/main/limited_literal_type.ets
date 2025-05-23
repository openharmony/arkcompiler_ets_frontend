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

let n1: 1 = 1;
let n2: 0.1 = 0.5
let f: true = true
let f: null;
let f: null = null;
let f: undefined = undefined;
let f: 'undefined';
let f: 's' = 333;
let f: 'y' = 'ssss';
let f: aaa = 'ssss';

class A{
  fd: "yyy"=111; 
  f4: string = 'eee'
  n1: 1 = 6;
  rg: undefined;
  ytt: 'y' = 'ssss';
  foo: aaa = 'ssss';
}
let x: number;
let persons : Record<string, OptionalPerson>;

let s = "123";
let c1 = s.length as number & 1;
let c2 = s.length & 1

function foo(p: 1) {} // CTE

let arr: 1[]; // CTE

let a = 1 as 1; // CTE

let c1 = s.length as (number & 1);  // error
let tup: [['arkts' | boolean, 1 | true, false], string[], number] = [['arkts', 1, false], ['arkts1', 'arkts2'], 1.5];
let a : 1| boolean = 1;
let b : [1] = [1]