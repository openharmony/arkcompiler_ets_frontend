/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

import { Something, SomethingFactory, SomethingBar, Bar, Select } from "./oh_modules/ohos_factory";

class C {
    static a = 5
    static b = 8
}

namespace H {
    export class G {}
}

let c = C
c = C
let g = H.G
g = H.G

let ca = C.a
let cb = C.b

let cc = new C()
let gg = new H.G()

function foo1(arg: typeof C) {}
foo1(C)

function foo2(arg: C) {
    return C
}

function foo3(arg: typeof H.G) {}
foo3(H.G)

function foo4(arg: H.G) {
    return H.G
}

class A {}
interface B {}
interface I {}
class CC extends A implements I, B {}

class D {
    constructor(arg: typeof C) {}
}
new D(C)

type X = D;

namespace test1 {
    class SomethingFoo extends Something { }
    namespace NS { export class SomethingFoo extends Something { } }

    let fact = SomethingFactory.getInstance();

    let x1 = fact.create1(SomethingFoo).beep();
    let x2 = fact.create1(SomethingBar).beep();
    let x3 = fact.create1(NS.SomethingFoo).beep();

    let x4 = fact.create2({ o: SomethingFoo });
    let x5 = fact.create2({ o: SomethingBar });
    let x6 = fact.create2({ o: NS.SomethingFoo });

    let x7 = fact.create3(() => SomethingFoo);
    let x8 = fact.create4(() => SomethingFoo);

    let x9 = new Bar(SomethingFoo);
}

enum Color { WHITE, BLUE, RED };
let color: Color = Color.RED;

for (let item = 0; item < Object.keys(Color).length; item++) {
    console.log(item);
}

foo2(() => C);

export { C as H };

// #14228
let data = new Select<Object>().from(C).eq('key').query(C); // Ok
invalid_func(C); // Ok
let a: any;
a.foo(C); // Ok

let col = 'WHITE';
console.log(Color[col])

// #14184
namespace NS {
    export enum E {
        A = 'A',
        B = 'B',
        C = 'C'
    }
}

let s: string = 'B';
let s2: string = NS.E[s];

for (let item = 0; item < Object.keys(NS.E).length; item++) {
    console.log(item);
}

/**
 * {@link C} - should not report error
 */
class JSDocClass {}