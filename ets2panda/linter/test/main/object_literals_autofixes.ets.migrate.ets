/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

// Following declarations are added to check that we don't generate new interfaces with names that already exist
import GeneratedObjectLiteralInterface_4 from 'x';
import * as GeneratedObjectLiteralInterface_7 from 'x';
import {
    GeneratedObjectLiteralInterface_8,
    foo as GeneratedObjectLiteralInterface_9
} from 'x';
interface GeneratedObjectLiteralInterface_11 {} 
class GeneratedObjectLiteralInterface_12 {}
function GeneratedObjectLiteralInterface_15() {}

class C<T> {}

function foo(x): number {
    return 1;
}

interface GeneratedObjectLiteralInterface_1 {
}
const o1: GeneratedObjectLiteralInterface_1 = {};
interface GeneratedObjectLiteralInterface_2 {
    hello: string;
}
const o2: GeneratedObjectLiteralInterface_2 = { hello: "world" };
interface GeneratedObjectLiteralInterface_3 {
    a: number;
    b: number;
}
const o3!: GeneratedObjectLiteralInterface_3 = {a: 1, b: 2};
interface GeneratedObjectLiteralInterface_5 {
    field: string;
    field1: number;
    field2: string;
    field3: number;
    field4: boolean;
    field5: boolean;
}
const o4: GeneratedObjectLiteralInterface_5 = { 
    field: "hello",
    field1: 2,
    field2: "world",
    field3: 4,
    field4: true,
    field5: false
};

// Properties with various types. Nested object literals
interface GeneratedObjectLiteralInterface_6 {
}
interface GeneratedObjectLiteralInterface_10 {
    a: number;
    b: string;
}
interface GeneratedObjectLiteralInterface_13 {
    q: number;
    w: number;
}
interface GeneratedObjectLiteralInterface_25 {
    a: number;
    b: string;
    c: boolean;
    d: C<number>;
    e: GeneratedObjectLiteralInterface_6;
    f: GeneratedObjectLiteralInterface_10;
    g: GeneratedObjectLiteralInterface_13;
}
const o5: GeneratedObjectLiteralInterface_25 = {
    a: 1,
    b: '2',
    c: true,
    d: new C<number>(),
    e: ({} as GeneratedObjectLiteralInterface_6),
    f: ({ a: 1, b: '2' } as GeneratedObjectLiteralInterface_10),
    g: ({ q: 10,
    w: 20 } as GeneratedObjectLiteralInterface_13),
};
interface GeneratedObjectLiteralInterface_14 {
    q: number;
    w: number;
}
interface GeneratedObjectLiteralInterface_16 {
    q: number;
    w: number;
}
interface GeneratedObjectLiteralInterface_21 {
    a: number;
    b: string;
    c: GeneratedObjectLiteralInterface_14;
    d: boolean;
    e: GeneratedObjectLiteralInterface_16;
}
const o6: GeneratedObjectLiteralInterface_21 = {
    a: 1,
    b: '2',
    c: ({ q: 10, w: 20 } as GeneratedObjectLiteralInterface_14),
    d: true,
    e: ({ q: 30, w: 40 } as GeneratedObjectLiteralInterface_16)
};

// Object literals inside another expression
interface GeneratedObjectLiteralInterface_17 {
    a: number;
    b: number;
}
interface GeneratedObjectLiteralInterface_18 {
    a: number;
    b: number;
}
const o7 = ({ a: 1, b: 2 } as GeneratedObjectLiteralInterface_17).a + ({ a: 3, b: 4 } as GeneratedObjectLiteralInterface_18).b;
interface GeneratedObjectLiteralInterface_19 {
    x: number;
    y: number;
}
interface GeneratedObjectLiteralInterface_20 {
    a: number;
    b: number;
    c: GeneratedObjectLiteralInterface_19;
    d: number;
}
interface GeneratedObjectLiteralInterface_23 {
    q: number;
    w: number;
}
interface GeneratedObjectLiteralInterface_27 {
    q: number;
    w: number;
}
const o8: GeneratedObjectLiteralInterface_20 = {
    a: 1, 
    b: 2,
    c: ({ x: 1, y: 2 } as GeneratedObjectLiteralInterface_19),
    d: foo(({ q: 1, w: 2 } as GeneratedObjectLiteralInterface_23).q + ({ q: 3, w: 4 } as GeneratedObjectLiteralInterface_27).w)
};

// Object literals inside class declaration
interface GeneratedObjectLiteralInterface_22 {
    a: number;
    b: number;
}
interface GeneratedObjectLiteralInterface_24 {
    a: number;
    b: number;
}
interface GeneratedObjectLiteralInterface_26 {
    a: number;
    b: number;
}
interface GeneratedObjectLiteralInterface_28 {
    c: number;
    d: number;
}
interface GeneratedObjectLiteralInterface_29 {
    e: number;
}
interface GeneratedObjectLiteralInterface_32 {
    f: number;
    g: number;
}
interface GeneratedObjectLiteralInterface_34 {
    a: number;
    b: number;
}
interface GeneratedObjectLiteralInterface_36 {
    c: number;
    d: number;
    e: number;
}
class D {
    f1: GeneratedObjectLiteralInterface_22 = {a: 1, b: 2};
    f2?: GeneratedObjectLiteralInterface_24 = {a: 1, b: 2};
    f3!: GeneratedObjectLiteralInterface_26 = {a: 1, b: 2};
    f4 = ({ c: 3, d: 4 } as GeneratedObjectLiteralInterface_28);
    f5 = ({ e: 5 } as GeneratedObjectLiteralInterface_29).e + ({ f: 6, g: 7 } as GeneratedObjectLiteralInterface_32).f;

    m() {
        let x: GeneratedObjectLiteralInterface_34 = {a:1, b:2};
        let y: GeneratedObjectLiteralInterface_36 = {c:1, d:2, e:3};
    }
}

// Object literals as function parameter initializer
interface GeneratedObjectLiteralInterface_30 {
    a: number;
    b: number;
}
function funInit(p: GeneratedObjectLiteralInterface_30 = { a: 1, b: 2 }) {}
function funInit2({a, b} = { a: 3, b: 4 }) {} // Not fixable, as in case of destructuring parameters, the contextual type of expression is implied by the binding pattern

// Object literals inside function declaration
interface GeneratedObjectLiteralInterface_31 {
    a: number;
    b: number;
}
interface GeneratedObjectLiteralInterface_33 {
    c: number;
    d: number;
}
interface GeneratedObjectLiteralInterface_35 {
    e: number;
    f: number;
}
interface GeneratedObjectLiteralInterface_37 {
    g: number;
    d: number;
}
interface GeneratedObjectLiteralInterface_38 {
    q: number;
    w: number;
}
interface GeneratedObjectLiteralInterface_39 {
    q: number;
    w: number;
}
function bar(): void {
    let a: GeneratedObjectLiteralInterface_31 = {a: 1, b: 2};
    let b: GeneratedObjectLiteralInterface_33 = {c: 3, d: 4};

    if (a.b > b.c) {
        let c: GeneratedObjectLiteralInterface_35 = {e: 5, f: 6};
    }

    let d: GeneratedObjectLiteralInterface_37 = {g: 7, d: foo(({ q: 1, w: 2 } as GeneratedObjectLiteralInterface_38).q + ({ q: 3, w: 4 } as GeneratedObjectLiteralInterface_39).w)};
}

const o9 = { 1: '1', '2': 2 }; // Not fixable, property name is string/numeric literal
const o10 = { [3]: 3 }; // Not fixable, computed property value
const o11 = { [o2.hello]: 'world' }; // Not fixable, computed property value

const anyVal: any = 1;
const o12 = { a: anyVal }; // Not fixable, type of property 'a' is not supported

let val = 1;
const o13 = { val }; // Fixable
const o14 = { ...o1 }; // Not fixable, property is not 'key:value' pair
class GeneratedObjectLiteralClass_1 {
    m() { }
}

const o15 = new GeneratedObjectLiteralClass_1(); // Fixable

const o16 = { // Not fixable, property 'c' is initialized with non-fixable nested object literal, and thus will always have unsupported type (object type literal)
    a: 1,
    b: '2',
    c: {
        q: 1,
        w: 2,
        e: anyVal // Not fixable, unsupported type
    }
}

class X<K> {}
class Y<Q extends X<Q>> {}
function captureFromLocalScope<T>(t: T): void {
    let v1 = {a: 1, b: '2', c: t}; // Not fixable, `c` references local type parameter `T`
    let v2 = {a: 1, b: '2', c: new X<T>()}; // Not fixable, `c` references local type parameter `T`
    let v3 = {a: 1, b: '2', c: new Y<X<T>>()}; // Not fixable, `c` references local type parameter `T`
  
    interface LocalType {
    a: number;
    b: string;
}
    let localTypeVar: LocalType = {a:1, b:'2'};
    let v4 = { x: localTypeVar }; // Non-fixable, `x` references type `LocalType` declared in local scope
  
    class LocalClass {x: number = 1};
    let v5 = { y: new LocalClass() }; // Non-fixable, `y` references type `LocalClass` declared in local scope
  
    let v6 = { z: LocalClass }; // Non-fixable, `z` references type `LocalClass` declared in local scope
}

// Record object literals
let rec1: Record<string, any> = {
    "a": 1,
    "b": 2,
    "c": 3
}

let rec2: Record<string | number, any> = {
    "foo": 1,
    "bar": 2,
    10: 'foo',
    20: 'bar',
    "baz": 3,
    'daz': 4
}

let rec3: Record<string | number, any> = { // Not fixable
    f1: 1,
    f2: 2,
    f3: 3,
    [val]: 4    // Not fixable, key is a computed value
}

interface NullableRecord {
    params?: Record<string, string>;
}
let rec4: NullableRecord = {
    params: {
        "key": '1',
        "message": '2'
    }
};