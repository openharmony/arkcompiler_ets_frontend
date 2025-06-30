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
'use static'

const arr: int[] = [1.0, 2.0, 3.0, 4.0];

for (let i: number = 0.0; i < arr.length; i++) {
    arr[i as int]; //legal
}

for (let i: number = 0.0; i < 100.0; i++) {
    console.log(i); //legal
}

const arr2: int[] = [1.0, 2.0, 3.0, 4.0];
for (let i: number = 0.0; i < 100.0; i++) {
    arr2[10] //should report
}

const arr3: int[] = [1.0, 2.0, 3.0, 4.0];
for (let i: number = 0.0; i < arr3.length; i++) {
    arr3[10] //should report
}

const arr4: int[] = [1.0, 2.0, 3.0, 4.0];
let x: int = 3.0;
for (let i: number = 0.0; i < arr4.length; i++) {
    arr4[x]; //should report
}

const arr5: int[] = [1.0, 2.0, 3.0, 4.0];
for (let i: number = 0.0; i < 10.0; i++) {
    arr5[i as int]; //should report
}


const arr6: int[] = [1.0, 2.0, 3.0, 4.0];
if (arr6.length > 10.0) {
    arr6[10]
}

const arr7: int[] = [1.0, 2.0, 3.0, 4.0];
if (arr7.length > 10.0) {
    return;
}

arr7[10]

const arr8: int[] = [1.0, 2.0, 3.0, 4.0];
const index: int = 9.0;
if (arr8.length > 10.0 && index > 0.0) {
    return;
}

arr8[index];

const arr9: int[] = [1.0, 2.0, 3.0, 4.0];
if (arr9.length > 10.0 && index > 0.0) {
    arr9[index];
}

const arr10: int[] = [1.0, 2.0, 3.0, 4.0];
if (index > 0.0) {
    arr10[index];
}

const arr10: int[] = [1.0, 2.0, 3.0, 4.0];
let newIndex: number = 10.0;
if (arr10.length > newIndex) {
    return;
}

newIndex = 22.0;

arr10[newIndex as int];

let arr: number[] = [0.0, 1.0, 2.0, 3.0, 4.0, 5.0]
for(let i: number = 0.0; i < arr.length; i++) {
arr[i as int] = arr[i as int] + 1.0;
}
for(let i: number = 0.0; i < arr.length; i++) {
i = 10.0;
arr[i as int] = arr[i as int] + 1.0;
}

let arr: number[] = [0.0, 1.0, 2.0, 3.0, 4.0, 5.0]
let idx: number = 2.0;
if(idx > 0.0 && idx < arr.length) {
arr[idx as int] = arr[idx as int] + 1.0;
}
if(idx > 0.0 && idx < arr.length) {
idx = 10.0;
arr[idx as int] = arr[idx as int] + 1.0;
}

let arr: number[] = [0.0, 1.0, 2.0, 3.0, 4.0, 5.0]
let idx: number = 0.0;
while(idx > 0.0 && idx < arr.length) {
arr[idx as int] = arr[idx as int] + 1.0;
idx++;
idx = 10.0;
}
while(idx > 0.0 && idx < arr.length) {
idx = 10.0;
arr[idx as int] = arr[idx as int] + 1.0;
}

let arr: number[] = [0.0, 1.0, 2.0, 3.0, 4.0, 5.0]
let idx: number = 0.0;
arr[idx as int];
arr[10];
if (arr.length > 10.0) {
arr[10] = 10.0;
}

function foo():int{
return 1.0;
}

arr[(44/3) as int];
arr[foo()];
arr[()=>{return 1}];
if(arr.length > foo()) {
arr[foo()];
}
if(arr.length > 44.0/3.0) {
arr[(4*4/3) as int];
}

let arr1:number[] = [1.0, 1.5,45.0,2.0]

function foo(i:number):number{
  return i;
}

arr1[3*5] = 23.0;
arr1[parseInt("16") as int] = 23.0;
arr1[foo(16) as int] = 23.0

let arr1:number[] = [1.0, 1.5,45.0,2.0]

arr1[Number.MAX_VALUE as int] = 23.0;
arr1[Number.MAX_SAFE_INTEGER as int] = 23.0;

let arr1:number[] = [1.0, 1.5,45.0,2.0]
function foo(i:number):number{
  return i;
}
arr1[(24)] = 23.0;
arr1[+24] = 23.0;
enum TE{
  AA = 12.0
}
arr1[TE.AA] = 12.0;

let a: string[] = [];
let b: Array<string> = new Array<string>(a.length);
for (let i: number = 0.0; i < a.length; i++) {
  b[i as int];
}