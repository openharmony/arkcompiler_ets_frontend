/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import assert = require('assert');

let fun1 = (a, b): number => {
  return a + b;
};

assert(fun1(1, 2) === 3, 'success');

let fun2 = a => a * a;

assert(fun2(2) === 4, 'success');

function fun3(a, b, c = 3) {
  return a + b + c;
}

assert(fun3(1, 2) === 6, 'success');

function fun4(a, b, ...args) {
  let res = a + b;
  args.forEach(function (value, index) {
    res += value;
  });

  return res;
}

assert(fun4(1, 2, 3, 4, 5) === 15, 'success');
