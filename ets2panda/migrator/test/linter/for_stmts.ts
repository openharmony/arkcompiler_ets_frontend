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

enum Mammals {
    Humans = 'Humans',
    Bats = 'Bats',
    Dolphins = 'Dolphins',
}

for(var m in Mammals) {
    console.log(m)
}

let someArray = [1, "string", false];
for (let entry of someArray) {
  console.log(entry); // 1, "string", false
}

let list = [4, 5, 6];
for (let i in list) {
  console.log(i); // "0", "1", "2",
}

for (let i of list) {
  console.log(i); // 4, 5, 6
}

let s : string = "abc";

for(let c of s) {
  console.log(c);
}

for (let i in s) {
  console.log(i);
}

let arr = ['z', 'x', 'y'];

for (let c of arr) {
  console.log(c);
}


let i:number, j:number, k:number;
// legal 'comma' operator
for( i = 1, j = 2, k = 3; ( i * j * k ) > 0; i++, k--, j +=2 ) {
	continue;
}
// illegal 'comma' operator
for( i = 1, (j=2,k=3); (i * j * k) > 0; i--, ( k++, j --)) {
   continue;
}

