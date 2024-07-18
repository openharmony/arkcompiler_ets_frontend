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

let count: int = 0;

function foo(a: int): char {
  count++;
  let x: char = c'd';
  return x;
}

function concatenate_float(prefix: String, number: float, suffix: String) : String {
  return (prefix + number + suffix);
}

function concatenate_compile_time() : void {
  let x: String = 5 + "10";
  assert x == "510";

  let y = 5 + "10";
  assert y == "510";
}

function main(): void {
  count = 0;
  let a: String = "abc";
  a += foo(123);

  assert a == "abcd";
  assert count == 1;

  let const_str: String = 'str' + c'a';
  assert const_str == "stra";

  assert concatenate_float('x', 1.0 as float, "y") == "x1y";

  concatenate_compile_time();
}
