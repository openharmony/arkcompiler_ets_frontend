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

import './short_test.ts'; // import from path

import { test } from './short_test.ts';

function withStmt() {
  const radius = 12;
  with (Math) {
    const area = PI * radius * radius;
  }
}

namespace X {
  export class C {}
  export interface I {
    f: number;
  }
  export const n = 15;
  export enum E {}
  export function foo(a: number): number {
    return a * a;
  }
  export type N = number;

  export namespace XX {
    export class D {}
  }

  console.log('Namespace X is initialized');
  {
    console.log('Block statement');
    const blockVar = 10;
  }
}
const xc = new X.C();
class IImpl implements X.I {
  f = 10;
}
const xn: X.N = X.foo(100);
const d: X.XX.D = new X.XX.D();

namespace Y.Z {
  export function bar(): void {
    const x = 200;
  }
}
Y.Z.bar();

// Namespace used as an object or type.
const x = X;
console.log(x.n);

const xxx = X.XX;
const dd = new xxx.D();

function xfoo(x: typeof X): void {
  x.foo(25);
}
xfoo(X);

function yzbar(yz: typeof Y.Z): void {
  yz.bar();
}
yzbar(Y.Z);

import { default as def } from 'module'; // default import

interface I {
  f: number;
}
export default I; // default interface export
export default function (n: number) {
  n++;
} // default function export
export default class MyClass {} // default class export

// type-only import
import type { APIResponseType } from './api';
import type * as P from 'foo';
import { type T1, type T2 as T3 } from 'foobar';

// type-only export
export type { TypeA as TypeB };
export { type TypeFoo as TypeBar };

// Re-exporting
export * from 'module1'; // Ok
export * as Utilities from 'module2'; // Ok
export { SomeFunction, SomeType as OtherType } from 'module3'; // Ok

class Point {}
export = Point;

import Validator = require('module');
import Button = Components.Button;

let m = require('moduleM');
const k = require('moduleK');

export { Point };
export { Point as P };
export default Point;

export { someFunction1 } from 'module3'
export { default as someFunction2 } from 'module3'
