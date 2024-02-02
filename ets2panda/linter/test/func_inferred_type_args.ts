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

import { bad_func } from "./dynamic_lib"

function choose<T>(x: T, y: T): T {
  return Math.random() < 0.5 ? x : y
}
let x = choose(10, 20);

function greet<T>(): T {
  return 'hello' as T;
}
let y = greet(); // T is 'unknown'

function foo<K, N = any>() {
  return 3;
}
foo(); // K is 'unknown'
foo<string>(); // N is 'any'
foo<number, string>();

function bar<T>(): T[] {
  return [];
}
bar(); // T is 'unknown'
bar<string>();

function baz<T>(m: Map<T, string>) {}
baz(new Map()); // T is 'any'
baz(new Map<number, string>());

function foobar<T>(t: T) {}
let z: any;
foobar(new Set<any>()); // T is 'Set<any>'
foobar([z]); // T is 'any[]'
foobar({a: 1, b: 2}); // T is Object literal type

let set = new Set(); // Type argument of constructor is 'unknown'
class C<T> {
  constructor(t?: T);
  constructor() {}
}
let c = new C(); // T is 'unknown'
c = new C<number>();
c = new C(bar()); // T is 'unknown[]'
c = new C(set); // T is 'Set<unknown>'
c = new C(new Set<any>()); // T is 'Set<any>'

const d: { ddd: [[]] };
d.ddd.push([]);

{
  let a: Promise<number> | undefined = undefined
  let b: undefined = undefined
  let c: [string, number] = ["abc", 0]
  let d: [any, number] = [10, 10]

  Boolean(a)
  Boolean(b)
  Boolean(c)
  Boolean(d)
}

Boolean(bad_func())
