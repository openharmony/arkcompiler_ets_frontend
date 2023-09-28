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

class B {}
class C extends B {
   constructor(private f: number = 1, protected s: string = "C") {
      super();
      console.log("In C ctor");
   }
   getf(): number { return this.f; }
   gets(): string { return this.s; }
}
class D {
   constructor(private f: number, public s: string) {
   }
   getID(): string { return this.s + this.f; }
}
class E {
   private id: string;
   constructor(public f: number, private s: string = "E") {
      this.id = this.s + this.f;
      console.log("In E ctor");
   }
   getID(): string { return this.id; }
}
