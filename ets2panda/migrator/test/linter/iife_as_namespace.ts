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

var F = (function() {
  function B(n) {
    this.p = n;
  }

  return B;
})();

F.staticProperty = 1; // #135

console.log("F.staticProperty = " + F.staticProperty); // #135

var C = (function() {
    class Cl {
        static static_value: string = "static_value";
        static any_value: any = "any_value";
        string_field : string = "string_field";
    }

    return Cl;
})();

C.prop = 2; // #135
console.log("C.prop = " + C.prop); // #135
console.log("C.static_value = " + C.static_value);
console.log("C.any_value = " + C.any_value);
console.log("C.string_field = " + C.string_field); // Not #135

var O = (function() {
    return {};
})();

O.objProp = 3; // #135
console.log("O.objProp = " + O.objProp); // #135
