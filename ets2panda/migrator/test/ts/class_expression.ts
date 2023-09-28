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

function foo(): void {
   let C = class M { 
               private f: M = this; 
               public getf(): M { return this.f; } 
           };
   let c = new C;
}

function bar(): void {
    let f = function(c: new () => object) { new c; }
    f(class { f: number = 1; })
}

function goo(n: number): void {
    switch (n) {
        case 0:
            let C = class { 
                        private s_: string; 
                        constructor(s: string) { this.s_ = s; }
                        public get s(): string { return this.s_; }
                        public set s(s: string) { this.s_ = s; }
                    }
            let c = new C("goo");
            break;
        case 1:
            function f(c: new(n: number) => object) { return new c(1); }
            f(class{ 
                  private f: number; 
                  constructor(n: number) { this.f = n; } 
              }
             );
    }
}
