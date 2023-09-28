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

function main(): void {
    let c = new C();
    let d2 = new D(10);
    let d3 = new D(20, "apple");

    // Local class
    class Local {}
    let local = new Local();

    // Class hiding
    {
        class C {
            constructor(x: number) {} 
        }
        let c = new C(0);
    }
}

class C { 
    constructor() {}
}
class D {
    private n: number;
    private s: string;
    constructor(x: number);
    constructor(x: number, y: string);
    constructor(x: number, y?: string) {
       this.n = x;
       if (y) this.s = y;
    }
}

type CCtor = {
    new(): C;
}

function foo(c: CCtor): void {
    let obj = new c;
}
