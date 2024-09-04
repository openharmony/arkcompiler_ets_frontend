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

let q: int = 1;  // variable in top-level scope
let s = "abc"

switch (q) {
  case 1: {
    q += 2; 
    break;
  }
  case 2: {
    assert(false)
    break;
  }
}

class TestException extends Exception {
}

assert(q == 3)
assert(s == "abc")

try {
  s += "cba";
  q += 5;
  throw new TestException();
}
catch (e: TestException) {
}
catch (e) {
  assert(false)
}

assert(q == 8)
assert(s == "abccba")

function main(): void {
  ETSGLOBAL.q = 1;
  let q: int;  // function main scope, top-level q is shadowed
  q = q + 30;
  assert(q == 30)
  assert(ETSGLOBAL.q == 1)

  assert(s == "abccba")
  s = "def";
  assert(s == "def")

  _$init$_();
   
  assert(s == "abccba")
  assert(q == 30)
  assert(ETSGLOBAL.q == 8)
}
