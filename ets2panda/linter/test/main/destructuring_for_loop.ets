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

const objects: { a: number; b: string }[] = [
  { a: 10, b: 'q' },
  { a: 20, b: 'w' },
  { a: 30, b: 'e' },
];
for (const { a, b } of objects) {
  console.log(a, b);
}

const arrays = [
  [1, 2],
  [3, 4],
  [5, 6],
];
for (const [q, w] of arrays) {
  console.log(q, w);
}

let a: number, b: string;
for ({ a, b } of objects) {
  console.log(a, b);
}

let x: number, y: number;
for ([x, y] of arrays) {
  console.log(x, y);
}

const people = [
  {
    name: 'Mike Smith',
    family: { mother: 'Jane Smith', father: 'Harry Smith' },
  },
  {
    name: 'Tom Jones',
    family: { mother: 'Norah Jones', father: 'Richard Jones' },
  },
];
let n: string, f: string;
for ({
  name: n,
  family: { father: f },
} of people) {
  console.log(`Name: ${n}, Father: ${f}`);
}