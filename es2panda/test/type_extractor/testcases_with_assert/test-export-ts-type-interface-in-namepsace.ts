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


declare function AssertType(value : any, type : string) : void;

namespace N {
  export namespace M {
    export class C {};

    export interface I {
      id: number,
      name: string
    }
  }
  export type t = number;
}

let obj: N.M.I = {id: 1, name: "a"};
let intNum: N.t = 1;
let doubleNum: N.t = 1.1;
let c: N.M.C = new N.M.C();

AssertType(obj.id, "number");
AssertType(obj.name, "string");
AssertType(intNum, "int");
AssertType(doubleNum, "double");
AssertType(c, "C");