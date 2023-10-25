/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

import {
  OhosLibC,
  OhosLibI,
  OhosLibIC,
  OhosLibII,
  OhosLibCC,
  OhosLibCI
} from './oh_modules/ohos_lib'

import {
  DynLibC,
  DynLibI,
  DynLibIC,
  DynLibII,
  DynLibCC,
  DynLibCI
} from './dynamic_lib'

class A {
  getName(): string { return 'A'; }
  getType(): string { return 'class'; }
}
class B {
  getName(): string { return 'B'; }
  getType(): string { return 'type'; }
}
function foo(a1: A, ...a2: A[]): void {
}
foo(new B, new A, new B);

let a =  new A;
a = new B;

let b: B = new A;

function bar(bArr: B[]): void {
  bArr[0] = new A;
}

let name = (new B as A).getName();

class C extends B {
  getBase(): string { return 'B'; }
}

function goo(): B {
  return new B;
}
let cl: C = goo() as C;

function zoo(b: B): void {
}
zoo(cl as B);

class IdentLibC {}
interface IdentLibI {}
interface IdentLibII extends IdentLibI {}
class IdentLibCC extends IdentLibC {}
class IdentLibCI implements IdentLibI {}

function fC(a: IdentLibC) {}
function fI(a: IdentLibI) {}

function fDC(a: DynLibC) {}
function fDI(a: DynLibI) {}

function fOC(a: OhosLibC) {}
function fOI(a: OhosLibI) {}

const c: IdentLibC = {};
const i: IdentLibI = {};
const ci: IdentLibCI = {};
const cc: IdentLibCC = {};
const ii: IdentLibII = {};

const dc: DynLibC = {};
const di: DynLibI = {};
const dci: DynLibCI = {};
const dcc: DynLibCC = {};
const dii: DynLibII = {};
const dic: DynLibIC = {};

const oc: OhosLibC = {};
const oi: OhosLibI = {};
const oci: OhosLibCI = {};
const occ: OhosLibCC = {};
const oii: OhosLibII = {};
const oic: OhosLibIC = {};

fC(c);    // OK
fC(i);    // ERR, no inheritance relation
fC(ci);   // ERR, no inheritance relation
fC(cc);   // OK
fC(ii);   // ERR, no inheritance relation
fI(c);    // ERR, no inheritance relation
fI(i);    // OK
fI(ci);   // OK
fI(cc);   // ERR, no inheritance relation
fI(ii);   // OK
fDC(c);   // OK, assignment to dynamic
fDC(i);   // OK, assignment to dynamic
fDC(ci);  // OK, assignment to dynamic
fDC(cc);  // OK, assignment to dynamic
fDC(ii);  // OK, assignment to dynamic
fDI(c);   // OK, assignment to dynamic
fDI(i);   // OK, assignment to dynamic
fDI(ci);  // OK, assignment to dynamic
fDI(cc);  // OK, assignment to dynamic
fDI(ii);  // OK, assignment to dynamic
fOC(c);   // OK, assignment to dynamic
fOC(i);   // OK, assignment to dynamic
fOC(ci);  // OK, assignment to dynamic
fOC(cc);  // OK, assignment to dynamic
fOC(ii);  // OK, assignment to dynamic
fOI(c);   // OK, assignment to dynamic
fOI(i);   // OK, assignment to dynamic
fOI(ci);  // OK, assignment to dynamic
fOI(cc);  // OK, assignment to dynamic
fOI(ii);  // OK, assignment to dynamic

fC(dc);   // ERR, no inheritance relation
fC(di);   // ERR, no inheritance relation
fC(dci);  // ERR, no inheritance relation
fC(dcc);  // ERR, no inheritance relation
fC(dii);  // ERR, no inheritance relation
fC(dic);  // ERR, no inheritance relation
fI(dc);   // ERR, no inheritance relation
fI(di);   // ERR, no inheritance relation
fI(dci);  // ERR, no inheritance relation
fI(dcc);  // ERR, no inheritance relation
fI(dii);  // ERR, no inheritance relation
fI(dic);  // ERR, no inheritance relation
fDC(dc);  // OK, assignment to dynamic
fDC(di);  // OK, assignment to dynamic
fDC(dci); // OK, assignment to dynamic
fDC(dcc); // OK, assignment to dynamic
fDC(dii); // OK, assignment to dynamic
fDC(dic); // OK, assignment to dynamic
fDI(dc);  // OK, assignment to dynamic
fDI(di);  // OK, assignment to dynamic
fDI(dci); // OK, assignment to dynamic
fDI(dcc); // OK, assignment to dynamic
fDI(dii); // OK, assignment to dynamic
fDI(dic); // OK, assignment to dynamic
fOC(dc);  // OK, assignment to dynamic
fOC(di);  // OK, assignment to dynamic
fOC(dci); // OK, assignment to dynamic
fOC(dcc); // OK, assignment to dynamic
fOC(dii); // OK, assignment to dynamic
fOC(dic); // OK, assignment to dynamic
fOI(dc);  // OK, assignment to dynamic
fOI(di);  // OK, assignment to dynamic
fOI(dci); // OK, assignment to dynamic
fOI(dcc); // OK, assignment to dynamic
fOI(dii); // OK, assignment to dynamic
fOI(dic); // OK, assignment to dynamic

fC(oc);   // ERR, no inheritance relation
fC(oi);   // ERR, no inheritance relation
fC(oci);  // ERR, no inheritance relation
fC(occ);  // ERR, no inheritance relation
fC(oii);  // ERR, no inheritance relation
fC(oic);  // ERR, no inheritance relation
fI(oc);   // ERR, no inheritance relation
fI(oi);   // ERR, no inheritance relation
fI(oci);  // ERR, no inheritance relation
fI(occ);  // ERR, no inheritance relation
fI(oii);  // ERR, no inheritance relation
fI(oic);  // ERR, no inheritance relation
fDC(oc);  // OK, assignment to dynamic
fDC(oi);  // OK, assignment to dynamic
fDC(oci); // OK, assignment to dynamic
fDC(occ); // OK, assignment to dynamic
fDC(oii); // OK, assignment to dynamic
fDC(oic); // OK, assignment to dynamic
fDI(oc);  // OK, assignment to dynamic
fDI(oi);  // OK, assignment to dynamic
fDI(oci); // OK, assignment to dynamic
fDI(occ); // OK, assignment to dynamic
fDI(oii); // OK, assignment to dynamic
fDI(oic); // OK, assignment to dynamic
fOC(oc);  // OK, assignment to dynamic
fOC(oi);  // OK, assignment to dynamic
fOC(oci); // OK, assignment to dynamic
fOC(occ); // OK, assignment to dynamic
fOC(oii); // OK, assignment to dynamic
fOC(oic); // OK, assignment to dynamic
fOI(oc);  // OK, assignment to dynamic
fOI(oi);  // OK, assignment to dynamic
fOI(oci); // OK, assignment to dynamic
fOI(occ); // OK, assignment to dynamic
fOI(oii); // OK, assignment to dynamic
fOI(oic); // OK, assignment to dynamic

c as IdentLibC;   // OK
i as IdentLibC;   // ERR, no inheritance relation
ci as IdentLibC;  // ERR, no inheritance relation
cc as IdentLibC;  // OK
ii as IdentLibC;  // ERR, no inheritance relation
c as IdentLibI;   // ERR, no inheritance relation
i as IdentLibI;   // OK
ci as IdentLibI;  // OK
cc as IdentLibI;  // ERR, no inheritance relation
ii as IdentLibI;  // OK
c as DynLibC;     // OK, assignment to dynamic
i as DynLibC;     // OK, assignment to dynamic
ci as DynLibC;    // OK, assignment to dynamic
cc as DynLibC;    // OK, assignment to dynamic
ii as DynLibC;    // OK, assignment to dynamic
c as DynLibI;     // OK, assignment to dynamic
i as DynLibI;     // OK, assignment to dynamic
ci as DynLibI;    // OK, assignment to dynamic
cc as DynLibI;    // OK, assignment to dynamic
ii as DynLibI;    // OK, assignment to dynamic
c as OhosLibC;    // OK, assignment to dynamic
i as OhosLibC;    // OK, assignment to dynamic
ci as OhosLibC;   // OK, assignment to dynamic
cc as OhosLibC;   // OK, assignment to dynamic
ii as OhosLibC;   // OK, assignment to dynamic
c as OhosLibI;    // OK, assignment to dynamic
i as OhosLibI;    // OK, assignment to dynamic
ci as OhosLibI;   // OK, assignment to dynamic
cc as OhosLibI;   // OK, assignment to dynamic
ii as OhosLibI;   // OK, assignment to dynamic

dc as IdentLibC;  // ERR, no inheritance relation
di as IdentLibC;  // ERR, no inheritance relation
dci as IdentLibC; // ERR, no inheritance relation
dcc as IdentLibC; // ERR, no inheritance relation
dii as IdentLibC; // ERR, no inheritance relation
dic as IdentLibC; // ERR, no inheritance relation
dc as IdentLibI;  // ERR, no inheritance relation
di as IdentLibI;  // ERR, no inheritance relation
dci as IdentLibI; // ERR, no inheritance relation
dcc as IdentLibI; // ERR, no inheritance relation
dii as IdentLibI; // ERR, no inheritance relation
dic as IdentLibI; // ERR, no inheritance relation
dc as DynLibC;    // OK, assignment to dynamic
di as DynLibC;    // OK, assignment to dynamic
dci as DynLibC;   // OK, assignment to dynamic
dcc as DynLibC;   // OK, assignment to dynamic
dii as DynLibC;   // OK, assignment to dynamic
dic as DynLibC;   // OK, assignment to dynamic
dc as DynLibI;    // OK, assignment to dynamic
di as DynLibI;    // OK, assignment to dynamic
dci as DynLibI;   // OK, assignment to dynamic
dcc as DynLibI;   // OK, assignment to dynamic
dii as DynLibI;   // OK, assignment to dynamic
dic as DynLibI;   // OK, assignment to dynamic
dc as OhosLibC;   // OK, assignment to dynamic
di as OhosLibC;   // OK, assignment to dynamic
dci as OhosLibC;  // OK, assignment to dynamic
dcc as OhosLibC;  // OK, assignment to dynamic
dii as OhosLibC;  // OK, assignment to dynamic
dic as OhosLibC;  // OK, assignment to dynamic
dc as OhosLibI;   // OK, assignment to dynamic
di as OhosLibI;   // OK, assignment to dynamic
dci as OhosLibI;  // OK, assignment to dynamic
dcc as OhosLibI;  // OK, assignment to dynamic
dii as OhosLibI;  // OK, assignment to dynamic
dic as OhosLibI;  // OK, assignment to dynamic

oc as IdentLibC;  // ERR, no inheritance relation
oi as IdentLibC;  // ERR, no inheritance relation
oci as IdentLibC; // ERR, no inheritance relation
occ as IdentLibC; // ERR, no inheritance relation
oii as IdentLibC; // ERR, no inheritance relation
oic as IdentLibC; // ERR, no inheritance relation
oc as IdentLibI;  // ERR, no inheritance relation
oi as IdentLibI;  // ERR, no inheritance relation
oci as IdentLibI; // ERR, no inheritance relation
occ as IdentLibI; // ERR, no inheritance relation
oii as IdentLibI; // ERR, no inheritance relation
oic as IdentLibI; // ERR, no inheritance relation
oc as DynLibC;    // OK, assignment to dynamic
oi as DynLibC;    // OK, assignment to dynamic
oci as DynLibC;   // OK, assignment to dynamic
occ as DynLibC;   // OK, assignment to dynamic
oii as DynLibC;   // OK, assignment to dynamic
oic as DynLibC;   // OK, assignment to dynamic
oc as DynLibI;    // OK, assignment to dynamic
oi as DynLibI;    // OK, assignment to dynamic
oci as DynLibI;   // OK, assignment to dynamic
occ as DynLibI;   // OK, assignment to dynamic
oii as DynLibI;   // OK, assignment to dynamic
oic as DynLibI;   // OK, assignment to dynamic
oc as OhosLibC;   // OK, assignment to dynamic
oi as OhosLibC;   // OK, assignment to dynamic
oci as OhosLibC;  // OK, assignment to dynamic
occ as OhosLibC;  // OK, assignment to dynamic
oii as OhosLibC;  // OK, assignment to dynamic
oic as OhosLibC;  // OK, assignment to dynamic
oc as OhosLibI;   // OK, assignment to dynamic
oi as OhosLibI;   // OK, assignment to dynamic
oci as OhosLibI;  // OK, assignment to dynamic
occ as OhosLibI;  // OK, assignment to dynamic
oii as OhosLibI;  // OK, assignment to dynamic
oic as OhosLibI;  // OK, assignment to dynamic

class Ct {
  a: number = 1
  b: string = ""
}

interface I {
  a: number
}

class Cz {
  x: Ct | null = new Ct();
  y: I = this.x as I
}

let x: Ct | null = new Ct();
let y: I = x as I

class X {}
class Y {}
class Z {}
class W extends X {}

function union(x: X, xy: X | Y, xz: X | Z, xyz: X | Y | Z, w: W, xw: X | W, zw: Z | W) {
  x = xy; // ERR, 'X | Y' assigned to 'X'
  xy = x; // OK

  xy = xz; // ERR, 'X | Z' assigned to 'X | Y'
  xz = xy; // ERR, 'X | Y' assigned to 'X | Z'

  xyz = xz; // OK
  xz = xyz; // ERR, 'X | Y | Z' assigned to 'X | Z'
  
  x = w; // OK
  w = x; // ERR, 'X' assigned to 'W' 

  x = xw; // OK
  xw = x; // OK

  xw = zw; // ERR, 'Z | W' assigned to 'X | W'
  zw = xw; // ERR, 'X | W' assigned to 'Z | W'
  
  xz = zw; // OK
  zw = xz; // ERR, 'X | Z' assigned to 'Z | W'
}