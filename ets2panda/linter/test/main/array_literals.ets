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

class C {
  a: any;
  b: any[];
  c: [number, number];
  d: number[];
}

function arrayLiteralsInVarDecl(): void {
  const a = [1, 2]; // NOW OK
  const b: any = [3, 4]; // NOW OK
  const c: any[] = [5, 6]; // OK
  const d: [number, number] = [7, 8]; // NOW OK
  const e: number[] = [9, 10]; // OK
  const f = [1, 'x', true]; // NOW OK
  const g: object[] = [2, 'y', false]; // OK

  const h: C = {
    a: [1, 2], // NOW OK
    b: [3, 4], // OK
    c: [5, 6], // NOW OK
    d: [7, 8], // OK
  };

  const x = [1, 2, 3][1]; // NOW OK
}

let a: number[];
let b: any;
let c: any[];
let d: [number, number];
let e: number[];
let f: [number, string, boolean];
let g: object[];
let h: C;

function arrayLiteralsInAssignment(): void {
  a = [1, 2]; // OK
  b = [3, 4]; // NOW OK
  c = [5, 6]; // OK
  d = [7, 8]; // NOW OK
  e = [9, 10]; // OK
  f = [1, 'x', true]; // NOW OK for ARR.LITERAL
  g = [2, 'y', false]; // OK

  h = {
    a: [1, 2], // NOW OK
    b: [3, 4], // OK
    c: [5, 6], // NOW OK
    d: [7, 8], // OK
  };
}

// Default parameter value
function foo(x = [1, 2]) {
  return x;
} // NOW OK
function foo2(x: any = [3, 4]) {
  return x;
} // NOW OK
function foo3(x: any[] = [5, 6]) {
  return x;
} // OK
function foo4(x: [number, number] = [7, 8]) {
  return x;
} // NOW OK
function foo5(x: number[] = [9, 10]) {
  return x;
} // OK

function arrayLiteralsInFunCall(): void {
  foo([1, 2]); // OK
  foo2([3, 4]); // NOW OK
  foo3([5, 6]); // OK
  foo4([7, 8]); // NOW OK
  foo5([9, 10]); // OK
}

// Return from function
function bar() {
  return [1, 2];
} // NOW OK
function bar2(): any {
  return [3, 4];
} // NOW OK
function bar3(): any[] {
  return [5, 6];
} // OK
function bar4(): [number, number] {
  return [7, 8];
} // NOW OK
function bar5(): number[] {
  return [9, 10];
} // OK

function arrayLiteralsInTernaryOp(): void {
  const condition = true;
  a = condition ? [1, 2] : [3, 4]; // OK
  b = condition ? [5, 6] : [7, 8]; // NOW OK
  c = condition ? [9, 10] : [11, 12]; // OK
  d = condition ? [13, 14] : [15, 16]; // NOW OK
  e = condition ? [17, 18] : [19, 20]; // OK
}

class P {
  n:number = 0;
  s:string = '';
}

let a1 = [ { n:1, s:"1" } as P,  { n:2, s:"2" } as P ]; // OK
let a2: P[] =  [ { n:3, s:"3" },  { n:4, s:"4" } ]; // OK
let a3 =  [ { n:1, s:"1" },  { n:2, s:"2" } ]; // NOT OK
