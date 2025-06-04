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

class X {}

const a = new X() instanceof Object; // true
const b = new X() instanceof X; // true

// left operand is a type:
const c = X instanceof Object; // Compile-time error
const d = X instanceof X; // Compile-time error

// left operand may be of any reference type, like number
const e = (5.0 as Number) instanceof Number; // false

const g = new Number(3) instanceof Number;

let bad2Number = 5.0 as Number;
let pi = 3.14;
bad2Number = pi as Number;

let bad2Boolean = true as Boolean;
bad2Boolean = a as Boolean;

const aa = this instanceof Object;
const bb = this instanceof X;

class A extends Error {
    constructor(message?: string) {
            super(message)
            console.log(this instanceof Error)
    }
}

let ce = new A()

// left operand is a type:
const fc = 3 instanceof Object; // Compile-time error
const fd = "s" instanceof Object; // Compile-time error

const ff = new String("d") instanceof Number;

var le = () => { return String instanceof Object };

class SomeClass {
    static readonly field = SomeClass instanceof Object;

    methodRet() {
        return SomeClass instanceof Object;
    }

    methodTestCondition(): boolean {
        if (SomeClass instanceof SomeClass) return true;
        return false;
    }

    methodWhileCondition() {
        while (SomeClass instanceof SomeClass) {
        }
    }

    methodDoWhileNegativeCondition() {
        do {
        } while (!SomeClass instanceof SomeClass)
    }
}
