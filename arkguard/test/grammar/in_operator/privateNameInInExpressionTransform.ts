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

class F {
  #f = 1;
  #fun() { }
  static #staticF = 2;
  static #staticMethod() { }
  check(a: any) {
    #f in a; // expect F's 'f' WeakMap
    #fun in a; // expect F's 'instances' WeakSet
    #staticF in a; // expect F's constructor
    #staticMethod in a; // expect F's constructor
  }
  precedence(a: any) {
    // '==' and '||' have lower precedence than 'in'
    // 'in'  naturally has same precedence as 'in'
    // '<<' has higher precedence than 'in'

    a == #f in a || a; // Good precedence: (a == (#f in a)) || a

    #f in a && #f in a; // Good precedence: (#f in a) && (#f in a)
  }
}

class Bar {
  #f = 1;
  check(a: any) {
    #f in a; // expect Bar's 'f' WeakMap
  }
}

export { }