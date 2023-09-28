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

let objlit = { f: 0, e: "" };

class C {
   f: number = 1;
   e: string = "C";
}

function foo(c: C): void {
   console.log(c.f);
   console.log(c.e);
}

function bar(): void {
   foo({ f: 2, e: "foo" });
}

function zoo(): void {
   let e = "zoo";
   let d: C = { f: 3, e };
   foo(d);
}

function goo(c: C): void {
   c = { f: 4, e: "goo" };
   foo(c);
}

class D {
   f: C = { f: 5, e: "D" };
}

function foobar(d: D): void {
   let f = 6;
   d.f = { f, e: "foobar" };
}
