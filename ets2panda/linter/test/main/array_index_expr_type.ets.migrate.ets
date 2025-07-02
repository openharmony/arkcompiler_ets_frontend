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

function foo(index:number){
  let an_array: number[] = [1.0, 2.0, 3.0]
  let a: number = an_array[index as int]
  let a1: number = an_array[(index + 1) as int]
  let a2: number = an_array[(index + 1.1) as int]
  let b: number = an_array[1.23 as int]
  let c = an_array[true]
  let d = an_array['index']
  let e = an_array[undefined]
  let f = an_array[null]
  let g: number = an_array[]
  let h: number = an_array[12. as int]
  let i: number = an_array[12.0 as int]
  let j: number = an_array[0]
  let k: number = an_array[Number.MAX_VALUE as int]
  let l: number = an_array[Number.MIN_VALUE as int]
  let m: number = an_array[Number.MAX_SAFE_INTEGER as int]
}

let array: number[] = [1.0, 2.0, 3.0]
const index_1: number = 1.3;
let index_2: number = 1.3;
let index_3: number = 1.0;
array[index_1 as int];
array[index_2 as int];
array[index_3 as int];
let index_4: int = 2.0
array[index_4];
const index_5: number = 1.0;
array[index_5 as int];

function getIndex(): number {
  return Math.random() * 10.0;
}
let array1: number[] = [1.0, 2.0, 3.0];
array1[getIndex() as int];

let array2: number[] = [1.0, 2.0, 3.0];
for (let i: number = 0.0; i < array2.length; i++) {
  console.log(array2[i as int]);
}

for (let i: int = 0.0; i < array2.length; i++) {
  console.log(array2[i]);
}

let arr1:number[] = [1.0, 2.0, 3.0]
enum TE{
  AA = 1.12
  BB = 0.0
}
arr1[TE.AA as int];
arr1[TE.BB];
arr1[+0];
arr1[-0];
arr1[+1];
arr1[-1];
arr1[1.1 as int];

let a:short = 1.0;
let b:byte = 1.0;
let c:int = 1.0;
let d:long = 1.0;

let arr:number[] = [1.0,2.0,3.0]
arr[true?1.3:1.2]
arr[a] = 1.0;
arr[b] = 1.0;
arr[c] = 1.0;
arr[d] = 1.0;

let test: number = 1.0;
arr[1 as int];
arr[test as int];