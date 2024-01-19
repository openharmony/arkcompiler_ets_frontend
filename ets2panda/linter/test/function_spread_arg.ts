/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

function foo(x, y, z) {
  console.log(x, y, z);
}

const args: [number, string, boolean] = [0, 'str', false];
foo(...args);

function bar(x, y, ...z) {
  console.log(x, y, z);
}

bar(-1, 0, ...args);

let arr: number[] = [ 1, 2, 3 ];
bar(-1, 0, ...arr);

function foo2(n:number, ...rest: number[]) {

  rest.values
}
function foo3(...rest: bigint[]) {}

let a1 = [0,1]
let a2 = [1,2,3,4,5]
let a3: number[] = [1,2,3,4,5]
let a4: Array<number> = [1,2,3,4,5]
let a5 = new Array(10)
let a6 = new Int8Array(10)
let a7 = new Uint8Array(10)
let a8 = new Uint8ClampedArray(10)
let a9 = new Int16Array(10)
let a10 = new Uint16Array(10)
let a11 = new Int32Array(10)
let a12 = new Uint32Array(10)
let a13 = new Float32Array(10)
let a14 = new Float64Array(10)
let a15 = new BigInt64Array(10)
let a16 = new BigUint64Array(10)

foo2(1, ...a1)
foo2(1, ...a2)
foo2(1, ...a3)
foo2(1, ...a4)
foo2(1, ...a5)
foo2(1, ...a6)
foo2(1, ...a7)
foo2(1, ...a8)
foo2(1, ...a9)
foo2(1, ...a10)
foo2(1, ...a11)
foo2(1, ...a12)
foo2(1, ...a13)
foo2(1, ...a14)
foo3(...a15)
foo3(...a16)

function fUnionArr(...a: (number | string)[]) {}
let x: (number | string)[] = [];
let y = [1, 'string', 10]
let z: [number, string, number] = [1, 'string', 10]

fUnionArr(...x);
/**
 * OK, spec 7.5.2 Type inference from Types of Elements
 * type is (number | string)[], it is inferred from types of the elements. 
 */
fUnionArr(...y);
/**
 * NOT OK
 * type is explicitly specified to be tuple
 */
fUnionArr(...z);
