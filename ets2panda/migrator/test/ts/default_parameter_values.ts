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

function foo(n: number, s: string = "", b: boolean = true): void {
   if (b) console.log("foo", s+n);
}

function bar(): void {
   foo(1);
   foo(2, "bar");
   foo(3, "foobar", false);
}

class C {
   foo(n: number = 0, s: string = ""): void {
      if (n) console.log("C.foo", s+n);
   }

   bar(): void {
      this.foo();
      this.foo(1);
      this.foo(2, "bar");
   }
}
