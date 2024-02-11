/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

class X {
    public foo: number

    constructor() {
       this.foo = 0
    }
}

class Y {
    public foo: number
    constructor() {
        this.foo = 0
    }
}

let x = new X()
let y = new Y()

console.log("Assign X to Y")
y = x

console.log("Assign Y to X")
x = y




interface Z {
    foo: number
 }

 // X implements interface Z, which makes relation between X and Y explicit.
 class C implements Z {
     public foo: number

     constructor() {
        this.foo = 0
     }
 }

 // Y implements interface Z, which makes relation between X and Y explicit.
 class C2 implements Z {
     public foo: number

     constructor() {
        this.foo = 0
     }
 }

 let x1: Z = new C()
 let y1: Z = new C2()

 console.log("Assign X to Y")
 y1 = x1 // ok, both are of the same type

 console.log("Assign Y to X")
 x1 = y1 // ok, both are of the same type