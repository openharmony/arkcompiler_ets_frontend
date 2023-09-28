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

class C {
   f: number = 1;
   e: string = "C";
   foo(): void { console.log("class C"); }
}

let c1: C = { f: 2, e: "global", foo(): void { console.log("global"); } };
let c2: C = { f: 3, e: "global", get e(): string { return this.e; } };


function bar(c: C): void {
   c.foo();
}

function zoo(): void {
   let e = "zoo";
   bar({ f: 3, e, foo(): void { console.log("zoo"); } });
}

function main(): void {
   bar(c);
   zoo();
}
