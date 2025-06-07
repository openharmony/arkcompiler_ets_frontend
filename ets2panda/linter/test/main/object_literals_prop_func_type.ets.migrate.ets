/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

type F = () => void;
interface FuncInterface {
  (x: number): string
  f?: number;
}

class A {
  a: F;
  b: Function;
  c: () => void;
  d: FuncInterface;
}

let a: A = {
  a: () => { console.log('Hello'); },
  b: () => { console.log('Bye'); },
  c: () => { console.log('Apple'); },
  d: (x: number) => x.toString(),
}

let q: F = () => {};
let w: Function = (x: number) => x * x;
let e = () => { console.log('Orange'); };
let r: FuncInterface = (x: number) => x.toString();

a = {
  a: q,
  b: w,
  c: e,
  d: r,
}

// #14569 - initialize field with 'Function' object
class B {
  f: Function = () => {};
}
let b: B = {
  f: Function
};