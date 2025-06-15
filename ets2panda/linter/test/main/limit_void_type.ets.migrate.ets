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


// Example 1: Basic function
function func1(): void { }
let a: undefined = ((): undefined => { func1(); return undefined; })();
// Example 2: Arrow function
const func2 = (): void => { };
let b: undefined = ((): undefined => { func2(); return undefined; })();
// Example 3: Class method
class Demo {
  method(): void { }
}
let c: undefined = ((): undefined => { new Demo().method(); return undefined; })();
// Example 4: Immediately Invoked Function Expression (IIFE)
let d: undefined = ((): undefined => { ((): void => { })(); return undefined; })();
// Example 5: Asynchronous function
async function asyncFunc(): Promise<void> { }
let e: undefined = ((): undefined => { await asyncFunc(); return undefined; })();
// Example 6: Function parameter
function wrapper(fn: () => void) {
  let f: undefined = ((): undefined => { fn(); return undefined; })();
}
// Example 7: Type assertion
function func3(): void { }
let g: undefined = ((): undefined => { func3() as void; return undefined; })();
// Example 8: Callback function
setTimeout((): void => { }, 1000.0);
let h: undefined = ((): undefined => { setTimeout(() => { }, 1000.0); return undefined; })();
// Example 9: Array operation
const funcArr: (() => void)[] = [() => { }];
let i: undefined = ((): undefined => { funcArr[0](); return undefined; })();
// Example 10: Object method
const obj = {
  action: (): void => { }
};
let j: undefined = ((): undefined => { obj.action(); return undefined; })();
// Example 11: Strict mode
// @ts-strict
function func4(): void { }
let k: undefined = ((): undefined => { func4(); return undefined; })();
// Example 12: Module export
export function exportedFunc(): void { }
let l: undefined = ((): undefined => { exportedFunc(); return undefined; })();
// Example 13: Generic function
function genericFunc<T>(): void { }
let m: undefined = ((): undefined => { genericFunc(); return undefined; })();
// Example 14: Function overloading
function overloadFunc(): void;
function overloadFunc(n: number): number;
function overloadFunc(n?: number) { return n; }
let n: undefined = ((): undefined => { overloadFunc(); return undefined; })();
// Example 15: Type alias
type VoidFunc = () => void;
const aliasFunc: VoidFunc = () => { };
let o: undefined = ((): undefined => { aliasFunc(); return undefined; })();
// Example 16: Interface implementation
interface Task {
  run(): void;
}
class Printer implements Task {
  run(): void { }
}
let p: undefined = ((): undefined => { new Printer().run(); return undefined; })();
// Example 17: Optional parameter
function withParam(param?: string): void { }
let q: undefined = ((): undefined => { withParam(); return undefined; })();
// Example 18: Rest parameter
function sum(...nums: number[]): void { }
let r: undefined = ((): undefined => { sum(1.0, 2.0, 3.0); return undefined; })();
// Example 19: This parameter
function withThis(this: Window): void { }
let s: undefined = ((): undefined => { withThis.call(window); return undefined; })();
// Example 20: Generator function
function* genFunc(): Generator<void> {
  yield;
}
let u: undefined = ((): undefined => { genFunc().next().value; return undefined; })();
// Example 21: Function currying
const curry = () => (): void => { };
let w: undefined = ((): undefined => { curry()(); return undefined; })();
// Example 22: Method chaining
class Chain {
  first(): this { return this; }
  last(): void { }
}
let x: undefined = ((): undefined => { new Chain().first().last(); return undefined; })();
// Example 23: Destructuring assignment
const GeneratedDestructArray_1 = [(): void => { }];
const func = GeneratedDestructArray_1[0];

let y: undefined = ((): undefined => { func(); return undefined; })();
// Example 24: Type mapping
interface Wrapper<T> {
    value: T;
}
const wrapped: Wrapper<() => void> = { value: () => { } };
let z: undefined = ((): undefined => { wrapped.value(); return undefined; })();
// Example 25: Conditional type
type Conditional<T> = T extends boolean ? () => void : never;
const condFunc: Conditional<boolean> = () => { };
let aa: undefined = ((): undefined => { condFunc(); return undefined; })();
// Example 26: Mixed type
interface Mixed {
  (): void;
  prop: string;
}
const mixed: Mixed = Object.assign(() => { }, { prop: "" });
let ab: undefined = ((): undefined => { mixed(); return undefined; })();
// Example 27: Recursive call
function recursive(): void {
  return recursive();
}
let ac: undefined = ((): undefined => { recursive(); return undefined; })();
// Example 28: Decorator function
function decorator() {
  return (target: any) => { };
}
@decorator()
class Decorated { }
let ad: undefined = ((): undefined => { decorator()(Decorated); return undefined; })();

function f1(): void { }

let a1 = f1(); // type `void` is used as value

a1 = f1(); // type `void` is used as value

let a2: undefined = undefined; // type `void` is used as type annotation

let a3: void[] = [f1()]; // type `void` is used as type annotation

a3 = [f1()]; // type `void` is used as value

a3[0] = f1(); // type `void` is used as value

let a4: undefined = ((): undefined => { f1(); return undefined; })(); // type `void` is used as type annotation

function f2(a: undefined) { } // type `void` is used as type annotation

f2(f1()); // type `void` is used as value

class A {
  f: undefined = undefined; // type `void` is used as type annotation

  m(p: undefined) { } // type `void` is used as type annotation

  constructor(a: undefined) { // type `void` is used as type annotation
    this.f = a;
  }
}

function f3(): undefined | Promise<void> { 
return undefined;
} // type `void` is not allowed in union type

class B {
  m(): undefined | number { 
return undefined;
} // type `void` is not allowed in union type
}

type ss = void;
let sspar: ss;

type ff = string;
let ffpar: ff;

let sread: readonly [void] = [undefined];

interface BT {
  qaq: Function;
}

class C {
  private cc?: BT;

  private d(): void {
    this.cc = {
      qaq: (caller?: string): void => this.qaqq(caller)
    }
  }
  private qaqq(caller?: string): void {
    return;
  }
}

function foo(): void { }
function bar(): void { }

let aa = '1';
let bb = aa === '1' ? foo() : bar(); // Error

aa === '1' ? foo() : bar(); // No error
let dd;
dd = aa === '1' ? foo() : bar(); // Error
interface testB {
  u: void;  // Error
  fooIf(): void;
}

function foo1():void{
    return foo(); // No Error
}

function foocfe(a: number): string | undefined {
  if (a >= 0.0) {
    return "a >= 0";
  }
}

function foocfe2(a: number): string | undefined {
  if (a < 0.0) {
    return undefined;
  }
  return "a >= 0";
}
function fooefc(): void { }
let ss: undefined = ((): undefined => { foo(); return undefined; })()
let t: undefined | number = ((): undefined | number => { foo(); return undefined; })()
let t2: undefined | number = ((): undefined | number => { 1.0; return undefined; })();

function greet(hour: number): string | undefined {
  if (hour < 12.0) {
    return undefined;
  } else if (hour < 18.0) {
    return "Good afternoon";
  } else {
    return undefined;
  }
}

function logOrReturn(flag: boolean): string | undefined {
  if (flag) {
    return "Flag is true";
  }
  console.log("Flag is false");
  return undefined;
}

function justLogs(): string | undefined {
  console.log("Hello!");

return undefined;
}

function getStatus(code: number): string | undefined {
  switch (code) {
    case 1.0: return "OK";
    case 2.0: return "Warning";
  }
}

function tryThing(): string | undefined {
  try {
    return "Worked!";
  } catch (e) {
    console.error(e);
  }
}