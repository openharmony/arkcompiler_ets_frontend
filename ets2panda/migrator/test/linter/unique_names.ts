/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

// Global-scoped duplicate declarations

import A from "x";
interface A { }
class A implements A {
    m();                // Not duplicate, method overload
    m(a?: number) {}    // Not duplicate, method overload
}

namespace A {
    export interface B { a: number; }
    export class B extends A {}
    export interface C { a: number; } // Not duplicate, interface C has two merging declarations
}

namespace A {
    export interface B { b: string; }
    export interface C { b: string; } // Not duplicate, interface C has two merging declarations
}

import * as B from "y";
interface B { }
class B { }

import { C, X as D, E, Y as F } from "z";  // E and F are not duplicates
interface C { }
class C extends A implements C { }

function D() {}
interface D {}

function X();               // Not duplicate, function overload
function X(x?: number) {    // Not duplicate, function overload
    let ab = new A.B();
}

export function unique_names() {
    // Function-scoped duplicate declarations

    let A: number = 1000;
    interface A { }

    let B: string = "Text";
    type B = number[];

    class C { }
    interface C { }

    function D () {}
    type D = number;

    function E () {}
    interface E { }

    // Destructuring declarations
    interface F { a: number; }
    interface H { s: string; }
    let [F, G, ...H] = [1, 2, 3, 4, 5];
    
    interface I { b: boolean; }
    interface K { i: I; }
    interface M { k: K; }
    let { I, J: { K, L: [M, N], O} } = { I: 10, J: { K: "foo", L: [30, 40], O: "bar" } };
    
    {
        // Block-scoped duplicate declarations.
        let A: number = 54;
        interface A { }
    }

    switch (A) {
        case 1:
            let XX = 10;
            type XX = number;

            function XY() {}
            break;
        case 25:
            interface XY {}

            function XZ() {}
            break;
        default:
            type XZ = string[];
            break;
    }
}

class PrivateIdentifiers {
    x: number;
    #x: string;

    y(x: number): number { return 10; }
    #y(x: number): number { return 20; }

    z: boolean;
    #z(x: number): number { return 30; }
}