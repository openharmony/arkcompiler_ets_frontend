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

enum Mammals {
  Humans = 'Humans',
  Bats = 'Bats',
  Dolphins = 'Dolphins',
}

for (const m in Mammals) {
  if (true) console.log(m);
}

/**
 * OK, spec 7.5.2 Type inference from Types of Elements
 * type is (number | string | boolean)[], it is inferred from types of the elements. 
 */
const someArray = [1, 'string', false];
for (const entry of someArray) {
  console.log(entry); // 1, "string", false
}

for (const entry of [1, 'string', false]) {
  console.log(entry); // 1, "string", false
}

/**
 * NOT OK
 * type is explicitly specified to be tuple
 */
const someTuple: [number, string, boolean] = [1, 'string', false];
for (const entry of someTuple) {
  console.log(entry); // 1, "string", false
}

const list = [4, 5, 6];
for (const i in list) {
  if (true) console.log(i); // "0", "1", "2",
}

for (const i of list) {
  console.log(i); // 4, 5, 6
}

for (const i of [4, 5, 6]) {
  console.log(i); // 4, 5, 6
}

const s = 'abc'; // type is 'abc'
for (const c of s) {
  console.log(c);
}

let s2 = 'abs' // type is string
for (const c of s2) {
  console.log(c);
}

for (const c of 'abc') {
  console.log(c);
}

for (const i in s) {
  if (true) console.log(i);
}

const arr = ['z', 'x', 'y'];

for (const c of arr) {
  console.log(c);
}

let i: number, j: number, k: number;
// legal 'comma' operator
for (i = 1, j = 2, k = 3; i * j * k > 0; i++, k--, j += 2) {
  continue;
}
// illegal 'comma' operator
for (i = 1, ((j = 2), (k = 3)); i * j * k > 0; i--, (k++, j--)) {
  continue;
}

const a1 = [0, 1];
const a2 = [1, 2, 3, 4, 5];
const a3: number[] = [1, 2, 3, 4, 5];
const a4: Array<number> = [1, 2, 3, 4, 5];
const a5 = new Array(10);
const a6 = new Int8Array(10);
const a7 = new Uint8Array(10);
const a8 = new Uint8ClampedArray(10);
const a9 = new Int16Array(10);
const a10 = new Uint16Array(10);
const a11 = new Int32Array(10);
const a12 = new Uint32Array(10);
const a13 = new Float32Array(10);
const a14 = new Float64Array(10);
const a15 = new BigInt64Array(10);
const a16 = new BigUint64Array(10);

for (const i of a1) {
  console.log(i);
}
for (const i of a2) {
  console.log(i);
}
for (const i of a3) {
  console.log(i);
}
for (const i of a4) {
  console.log(i);
}
for (const i of a5) {
  console.log(i);
}
for (const i of a6) {
  console.log(i);
}
for (const i of a7) {
  console.log(i);
}
for (const i of a8) {
  console.log(i);
}
for (const i of a9) {
  console.log(i);
}
for (const i of a10) {
  console.log(i);
}
for (const i of a11) {
  console.log(i);
}
for (const i of a12) {
  console.log(i);
}
for (const i of a13) {
  console.log(i);
}
for (const i of a14) {
  console.log(i);
}
for (const i of a15) {
  console.log(i);
}
for (const i of a16) {
  console.log(i);
}

const a17: (number | string)[] = []

for (const i of a17) {
  console.log(i)
}

class P<T> extends Array<T> {
  foo() {
    for (let t of this) {
      console.log(t)
    }
  }
}

let a18 = new P<number>(1, 2, 3)
a18.foo()
for (let t of a18) {
  console.log(t)
}

class PN extends Array<number> {
  foo() {
    for (let t of this) {
      console.log(t)
    }
  }
}

let a19 = new PN(1, 2, 3)
a19.foo()
for (let t of a19) {
  console.log(t)
}

class MyInt8Array extends Int8Array {}
class MyUint8Array extends Uint8Array {}
class MyUint8ClampedArray extends Uint8ClampedArray {}
class MyInt16Array extends Int16Array {}
class MyUint16Array extends Uint16Array {}
class MyInt32Array extends Int32Array {}
class MyUint32Array extends Uint32Array {}
class MyFloat32Array extends Float32Array {}
class MyFloat64Array extends Float64Array {}
class MyBigInt64Array extends BigInt64Array {}
class MyBigUint64Array extends BigUint64Array {}

const a20 = new MyInt8Array(10);
const a21 = new MyUint8Array(10);
const a22 = new MyUint8ClampedArray(10);
const a23 = new MyInt16Array(10);
const a24 = new MyUint16Array(10);
const a25 = new MyInt32Array(10);
const a26 = new MyUint32Array(10);
const a27 = new MyFloat32Array(10);
const a28 = new MyFloat64Array(10);
const a29 = new MyBigInt64Array(10);
const a30 = new MyBigUint64Array(10);

for (const i of a20) {
  console.log(i);
}
for (const i of a21) {
  console.log(i);
}
for (const i of a22) {
  console.log(i);
}
for (const i of a23) {
  console.log(i);
}
for (const i of a24) {
  console.log(i);
}
for (const i of a25) {
  console.log(i);
}
for (const i of a26) {
  console.log(i);
}
for (const i of a27) {
  console.log(i);
}
for (const i of a28) {
  console.log(i);
}
for (const i of a29) {
  console.log(i);
}
for (const i of a30) {
  console.log(i);
}

class A<type1, type2> extends Map<type1, type2> {}
class B<type> extends Set<type> {}
class C extends String {}

let map = new Map([["a", 1], ["b", 2], ["c", 3]]);
let derivedFromMap = new A([["d", 4], ["e", 5], ["f", 6]]);
let set = new Set<number>([1, 2, 3]);
let derivedFromSet = new B<number>([4, 5, 6]);
let str = "hello";
let derivedFromString = new C("world")

for (let i of map) {
  console.log(i);
}

for (let i of derivedFromMap) {
  console.log(i);
}

for (let i of set) {
  console.log(i);
}

for (let i of derivedFromSet) {
  console.log(i);
}

for (let i of str) {
  console.log(i);
}

for (let i of derivedFromString) {
  console.log(i);
}
