/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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


let a = 1;
let b = 2;
const c = 3;
const d = 4;
var e = 5;
var f = 6;

class C1 {
  static {
    let a = 11;
    let b = 22;
    const c = 33;
    const d = 44;
    var e = 55;
    var f = 66;
    // the variables are in local scope of static blocks
    print(a, b, c, d, e, f);
  }
}

function foo() {
  let a = 11;
  const c = 33;
  var e = 55;

  class C2 {
    static {
      let a = 111;
      let b = 222;
      const c = 333;
      const d = 444;
      var e = 555;
      var f = 666;
      // the variables are in local scope of static blocks
      print(a, b, c, d, e, f);
    }
  }
  // the variables are in function scope
  print(a, b, c, d, e, f);
}

foo();

// the variables are in global scope, var in static blocks in classes will not be hoisted to the top level
print(a, b, c, d, e, f);