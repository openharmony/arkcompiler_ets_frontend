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

class A {
   private num: number;
   protected str: string = "A";
   constructor(n: number) {
      this.num = n;
   }
   protected foo(): number {
      return this.num*this.num;
   }
}

class B extends A {
   private id: string;
   constructor(n: number, s: string) {
      super(n);
      this.id = s;
   }
   foo(): number {
      let slen = this.str.length;
      return super.foo() + slen*slen;
   }
   private getId(): string {
      return "B" + this.id;
   }
   bar(): string {
      return super.str + this.getId();
   }
   goo(): string {
    return this["id"] + super["str"];
   }
}
