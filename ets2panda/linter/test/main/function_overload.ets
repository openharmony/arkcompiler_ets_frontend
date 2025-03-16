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

function makeDate(timestamp: number): Date;
function makeDate(m: number, d: number, y: number): Date;
function makeDate(mOrTimestamp: number, d?: number, y?: number): Date {
  if (d !== undefined && y !== undefined) {
    return new Date(y, mOrTimestamp, d);
  } else {
    return new Date(mOrTimestamp);
  }
}
const d1 = makeDate(12345678);
const d2 = makeDate(5, 5, 5);

function fn(x: string): string;
function fn(x: number): string;
function fn(x: string | number): string {
  return 'foo';
}

class C {
  constructor(x: number, y: string);
  constructor(s: string);
  constructor(xs: any, y?: any) {
    if (typeof xs === 'string') {
      const lower = xs.toLowerCase();
    }
  }

  m(n: number): void;
  m(s: string): void;
  m(): void {
    const n = 100 + 200;
  }
}
let c = new C(10, 'foo');
c = new C('bar');
c.m(100);
c.m('bazz');

abstract class AbstractClass {
  abstract foo(n: number): void;

  bar(s: string): void {
    console.log(s);
  }

  abstract baz(s: string): void; // Overload
  abstract baz(n: number): number; // Overload
}

declare class DeclareClass {
  constructor();

  foo(): void;

  bar(s: string): number;

  baz(s: string): void; // Overload
  baz(n: number): number; // Overload
}

declare function foobar(n: number): void; // Overload
declare function foobar(s: string): string; // Overload

declare function barbaz(b: boolean): void;

namespace X {
  function foo(x: number): void; // Overload
  function foo(): void {
    const n = 300 + 400;
  } // Overload

  export function bar(s: string): string; // Overload
  export function bar(n: number): string; // Overload
  export function bar(arg: number | string): string {
    // Overload
    return arg.toString();
  }
}

function f(): void {
  function localFun(n: number): void;
  function localFun(s: string): void;
  function localFun(): void {
    const n = 500 + 600;
  }
}
interface I {
  foo(x: number): void; // Overload
  foo(s: string): number; // Overload
}

class StaticBlock {
  static {
    function foo(x: number): void; // Overload
    function foo(s: string): void; // Overload
    function foo(): void {
      const n = 700 + 800;
    }
  }
}
