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

function gets(): string {
  return 'ss';
}

const b0 = true;

const c0 = b0 && true;
const c1 = true && '3';
const c2 = gets() && false;
const c3 = 5 && 6;

const d0 = false || b0;
const d1 = ~'3' || true;
const d2 = false || gets();
const d3 = 4 || 5;

console.log(c1);
console.log(c2);
console.log(c3);
console.log(d1);
console.log(d2);
console.log(d3);

const varAny: any = null;

const add0 = 2 + 2;
const add1 = '2' + '2';
const add2 = '2' + varAny;
const add3 = varAny + '2';
const add4 = varAny + 2;
const add5 = 6 + varAny;
const add6 = '2' + 2;
const add7 = 2 + '2';

enum Const {
  PI = 3.14,
  E = 2.7818,
}
enum State {
  OK = 'ok',
  FAULT = 'fail',
}

const b1 = 7 ^ varAny;
const b2 = 7 | varAny;
const b3 = 7 & varAny;

const b4 = 7 << varAny;
const b5 = 7 >> varAny;
const b6 = 7 >>> varAny;

const b7 = varAny << 1;
const b8 = varAny >> 2;
const b9 = varAny >>> 3;

const b11 = 7 ^ Const.PI;
const b12 = 7 | Const.E;
const b13 = 7 & Const.PI;

const b14 = 7 << Const.PI;
const b15 = 7 >> Const.E;
const b16 = 7 >>> Const.PI;

const b17 = Const.PI << 1;
const b18 = Const.E >> 2;
const b19 = Const.PI >>> 3;

const b31 = State.OK ^ 7;
const b32 = 7 | State.FAULT;
const b33 = 7 & State.OK;

const b34 = 7 << State.OK;
const b35 = 7 >> State.FAULT;
const b36 = 7 >>> State.OK;

const b37 = State.FAULT << 1;
const b38 = State.OK >> 2;
const b39 = State.FAULT >>> 3;

const a000 = ((k = 10), 2 + 7);

function foo(n: number, m: number): number {
  return (n/m) + ((n%m) ? 1 : 0);
}

const b40 = 7 & 5.5;
const b41 = 5.5 & b40;
const b42 = 2 | 5.5;
const b43 = 5.5 | b42;
const b44 = 4 ^ 5.5;
const b45 = 5.5 ^ b44;


let e1 = Const.PI + Const.E;  // OK
let e2 = State.FAULT + State.OK; // OK
let e3 = "State: " + State.FAULT; // OK
let e4 = "Const = " + Const.PI; // OK

let f1 = Const.PI + State.FAULT; // Error
let f2 = State.OK + Const.E; // Error
