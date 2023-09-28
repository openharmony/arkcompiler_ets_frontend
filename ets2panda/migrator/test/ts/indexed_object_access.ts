/*
 * Copyright (c) 2022-2022 Huawei Device Co., Ltd.
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

class C {
    [s: string]: string;
    foo: string = "string";
}

class N {
    [n: number]: number;
    10: number = 100;
}

let cobj = new C;
let s = cobj["foo"];

let nobj = new N;
let n = nobj[10]; 

enum E {
   K,
   L = 10,
   M
}

let a = E["M"];
