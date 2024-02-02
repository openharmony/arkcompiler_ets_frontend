/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

function* countAppleSales() {
  const saleList = [3, 7, 5];
  for (let i = 0; i < saleList.length; i++) {
    yield saleList[i];
  }
}

const foo = function* () {
  yield 'a';
  yield 'b';
  yield 'c';
};
let str = '';
for (const val of foo()) {
  str = str + val;
}
console.log(str); // Expected output: "abc"

class MyGenerator {
  public *getValues() {
    // you can put the return type Generator<number>, but it is ot necessary as ts will infer
    let index = 1;
    while (true) {
      yield index;
      index = index + 1;

      if (index > 10) {
        break;
      }
    }
  }
}

function* func1() {
  yield 42;
}
function* func2() {
  yield* func1();
}
const iterator = func2();
console.log(iterator.next().value); // Expected output: 42

function* g1() {
  yield 2;
  yield 3;
  yield 4;
}
function* g2() {
  yield 1;
  yield* g1();
  yield 5;
}
const gen = g2();
console.log(gen.next()); // {value: 1, done: false}
console.log(gen.next()); // {value: 2, done: false}
console.log(gen.next()); // {value: 3, done: false}
console.log(gen.next()); // {value: 4, done: false}
console.log(gen.next()); // {value: 5, done: false}
console.log(gen.next()); // {value: undefined, done: true}
