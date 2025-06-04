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

import { COh, Cb1Oh, Cb2Oh, F1Oh, F2Oh } from "./oh_modules/oh_import";
import { CGood, Cb1Good, Cb2Good, F1Good, F2Good } from "./ignore_files/good";
import {
  CNode,
  Cb1Node,
  Cb2Node,
  F1Node,
  F2Node,
} from "./node_modules/node_import";

class CLoc {}

export type Cb1Loc = (a: number, f?: string) => number;
export type Cb2Loc = (a: any, f?: string) => number;

export function F1Loc(cb?: Cb1Loc) {}
export function F2Loc(cb?: Cb2Loc) {}

// ====================
// #13760.1
let cb1: Cb1Oh = (arg) => arg;
let cb2: Cb2Oh = (arg) => arg;

let cb3: Cb1Good = (arg) => arg;
let cb4: Cb2Good = (arg) => arg;

let cb5: Cb1Node = (arg) => arg;
let cb6: Cb2Node = (arg) => arg;

let cb7: Cb1Loc = (arg) => arg;
let cb8: Cb2Loc = (arg) => arg;

F1Oh(cb1);
F1Oh((arg) => arg);
F2Oh(cb2);
F2Oh((arg) => arg);
F2Oh((arg: number) => arg);

F1Good(cb3);
F1Good((arg) => arg);
F2Good(cb4);
F2Good((arg) => arg);
F2Good((arg: number) => arg);

F1Node(cb5);
F1Node((arg) => arg);
F2Node(cb6);
F2Node((arg) => arg);
F2Node((arg: number) => arg);

F1Loc(cb7);
F1Loc((arg) => arg);
F2Loc(cb8);
F2Loc((arg) => arg);
F2Loc((arg: number) => arg);
// #13760.1
// ====================

// ====================
// #13760.2
export interface ILoc {
  fld1: number;
  fld2?: COh;
  fld3?: CGood;
  fld4?: CNode;
  fld5?: CLoc;
}

function f1(a: ILoc) {
  let v1 = a.fld1;
  let v2 = a.fld2;
  let v3 = a.fld3;
  let v4 = a.fld4;
  let v5 = a.fld5;
}
// #13760.2
// ====================

// additional tests

function fg1l1(cb: Cb1Good | Cb1Loc) {}
function fg1l2(cb: Cb1Good | Cb2Loc) {}
function fg2l1(cb: Cb2Good | Cb1Loc) {}
function fg2l2(cb: Cb2Good | Cb2Loc) {}

fg1l1((arg) => arg);
fg1l2((arg) => arg);
fg2l1((arg) => arg);
fg2l2((arg) => arg);
fg1l1((arg: number) => arg);
fg1l2((arg: number) => arg);
fg2l1((arg: number) => arg);
fg2l2((arg: number) => arg);

function fo1l1(cb: Cb1Oh | Cb1Loc) {}
function fo1l2(cb: Cb1Oh | Cb2Loc) {}
function fo2l1(cb: Cb2Oh | Cb1Loc) {}
function fo2l2(cb: Cb2Oh | Cb2Loc) {}

fo1l1((arg) => arg);
fo1l2((arg) => arg);
fo2l1((arg) => arg);
fo2l2((arg) => arg);
fo1l1((arg: number) => arg);
fo1l2((arg: number) => arg);
fo2l1((arg: number) => arg);
fo2l2((arg: number) => arg);

function fo1n1(cb: Cb1Oh | Cb1Node) {}
function fo1n2(cb: Cb1Oh | Cb2Node) {}
function fo2n1(cb: Cb2Oh | Cb1Node) {}
function fo2n2(cb: Cb2Oh | Cb2Node) {}

fo1n1((arg) => arg);
fo1n2((arg) => arg);
fo2n1((arg) => arg);
fo2n2((arg) => arg);
fo1n1((arg: number) => arg);
fo1n2((arg: number) => arg);
fo2n1((arg: number) => arg);
fo2n2((arg: number) => arg);

function fg1l1opt(cb?: Cb1Good | Cb1Loc) {}
function fg1l2opt(cb?: Cb1Good | Cb2Loc) {}
function fg2l1opt(cb?: Cb2Good | Cb1Loc) {}
function fg2l2opt(cb?: Cb2Good | Cb2Loc) {}

fg1l1opt((arg) => arg);
fg1l2opt((arg) => arg);
fg2l1opt((arg) => arg);
fg2l2opt((arg) => arg);
fg1l1opt((arg: number) => arg);
fg1l2opt((arg: number) => arg);
fg2l1opt((arg: number) => arg);
fg2l2opt((arg: number) => arg);

function fo1l1opt(cb?: Cb1Oh | Cb1Loc) {}
function fo1l2opt(cb?: Cb1Oh | Cb2Loc) {}
function fo2l1opt(cb?: Cb2Oh | Cb1Loc) {}
function fo2l2opt(cb?: Cb2Oh | Cb2Loc) {}

fo1l1opt((arg) => arg);
fo1l2opt((arg) => arg);
fo2l1opt((arg) => arg);
fo2l2opt((arg) => arg);
fo1l1opt((arg: number) => arg);
fo1l2opt((arg: number) => arg);
fo2l1opt((arg: number) => arg);
fo2l2opt((arg: number) => arg);

function fo1n1opt(cb?: Cb1Oh | Cb1Node) {}
function fo1n2opt(cb?: Cb1Oh | Cb2Node) {}
function fo2n1opt(cb?: Cb2Oh | Cb1Node) {}
function fo2n2opt(cb?: Cb2Oh | Cb2Node) {}

fo1n1opt((arg) => arg);
fo1n2opt((arg) => arg);
fo2n1opt((arg) => arg);
fo2n2opt((arg) => arg);
fo1n1opt((arg: number) => arg);
fo1n2opt((arg: number) => arg);
fo2n1opt((arg: number) => arg);
fo2n2opt((arg: number) => arg);
