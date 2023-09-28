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

function foo(arg: number|string): number {
   return typeof arg === "string" ? arg.length : arg;
}

class C {
   f: number;
   s?: string;
   static ss?: string;
   constructor(f: number, s: string) {
      this.f = f;
      this.s = s;
      C.ss = s + f;
   }
}

function bar(): void {
   let o = new C(1, "two");
   if ("s" in o) delete o.s;
   delete C.ss;
}

