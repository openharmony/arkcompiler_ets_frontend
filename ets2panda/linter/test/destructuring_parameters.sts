/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

function drawText({ text = '', position: [x, y] = [0, 0] }): void { // NOT OK
  // Draw text
}
drawText({ text: 'Figure 1', position: [10, 20] });

const hello = ({ // NOT OK
  firstName,
  lastName,
}: {
  firstName: string;
  lastName: string;
}): string => `Hello ${firstName} ${lastName}`;
console.log(hello({ firstName: 'Karl', lastName: 'Marks' }));

const person = { firstName: 'Adam', lastName: 'Smith' };
console.log(hello(person));

interface I {
  d: number
}

function f1({d = 1}: I) { // NOT OK
}
f1({d:2})

function f2({d = 1}: {d: number}) { // NOT OK
}
f2({d:2})

function f3({x, ...y}) { // NOT OK
  console.log(x);
  Object.keys(y).forEach(k => console.log(k, y[k]))
}
f3({x: 1, b: 2, c: 3})

function f4([a, b]): void {
  console.log(a, b);
}
f4(['Hello', 'Wolrd']);

function f5([a, b]: number[]): void {
  console.log(a, b);
}
f5([1, 2, 3]);

function f6([a, [b, c]]): void {
  console.log(a, b, c);
}
f6([1, [2, 3]]);

function f7([a, b, ...c]) { // NOT OK
  console.log(a, b, c);
}
f7([1, 2, 3, 4])

function f8([a, b, [c, ...d]]) { // NOT OK
  console.log(a, b, c, d);
}
f8([1, 2, [3, 4, 5]])

function f9([a, {b, c}]): void { // NOT OK
  console.log(a, b, c);
}
f9([1, {b: 2, c: 3}]);

function f10([a, [b, {c: d, e: f}]]): void { // NOT OK
  console.log(a, b, d, f);
}
f10([1, [2, {c : 3, e: 4}]]);

function f11([a, b]: Set<number>): void { // NOT OK
  console.log(a, b);
}
f11(new Set([1, 2, 3, 4]));
