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
import { fooOh, barOh } from './oh_modules/ohos_lib'
type ESValue = any

class A<T> {}

let g1: ESValue
let g2: ESValue[]
let g3: A<ESValue>

class B {
    f1: ESValue
    f2: ESValue[]
    f3: A<ESValue>

    constructor(p1: ESValue, p2: ESValue[], p3: A<ESValue>) {
        this.f1 = p1
        this.f2 = p2
        this.f3 = p3
    }

    foo1(p1: ESValue, p2: ESValue[], p3: A<ESValue>): ESValue {
        return p1
    }

    foo2(p1: ESValue, p2: ESValue[], p3: A<ESValue>): ESValue[] {
        return p2
    }

    foo3(p1: ESValue, p2: ESValue[], p3: A<ESValue>): A<ESValue> {
        return p3
    }
}

function bar1(p1: ESValue, p2: ESValue[], p3: A<ESValue>): ESValue {
    return p1
}

function bar2(p1: ESValue, p2: ESValue[], p3: A<ESValue>): ESValue[] {
    return p2
}

function bar3(p1: ESValue, p2: ESValue[], p3: A<ESValue>): A<ESValue> {
    return p3
}

function ff(): {x: number} {
    return {x: 10}
}

function baz(p1: ESValue, p2: ESValue[], p3: A<ESValue>): void {
    const c1: ESValue = p1;
    const c2: ESValue[] = p2
    const c3: A<ESValue> = p3

    let v1: ESValue = p1
    let v2: ESValue[] = p2
    let v3: A<ESValue> = p3

    v1 = c1
    v2 = c2
    v3 = c3

    v1.x = 10
    v1.foo()
    v1[10] = 20
    v1(20)

    v1 = {}
    v1 = "abc"
    v1 = ff()
    v1 = [1, 2]
    v1 = [p1, c1]
    v1 = [p1, c1, "abc"]
    v1 = new A<string>()

    let v11: ESValue = {}
    let v12: ESValue = "abc"
    let v13: ESValue = ff()
    let v14: ESValue = [1, 2]
    let v15: ESValue = [p1, c1]
    let v16: ESValue = [p1, c1, "abc"]
    let v17: ESValue = new A<string>()

    let n1: number = v1
    n1 = v1
    let n2: number = p1 as number
}

export let obj = new ESValue();

type t1 = ESValue
type t2 = ESValue[]

export type t3 = ESValue
export type t4 = ESValue[]

export type t5 = t3
export type t6 = t4[]

export function foo1(): any {
    let a: ESValue = "STRING";
    return a
}

export function foo2(a: ESValue): ESValue {
    return a;
}

export function foo3(a: t3): t3 {
    return a;
}

foo2(5)
foo3(5)
foo2("asd")
foo3("asd")
foo2(null)
foo3(null)
foo2(undefined)
foo3(undefined)

export function foo4(a: ESValue[]): ESValue {
    return a;
}

export function foo5(a: t3[]): t3 {
    return a;
}

foo4([2, 3])
foo5([2, 3])
foo4(["str1", "str2"])
foo5(["str1", "str2"])
let n: ESValue
n = null

foo4(n)
foo5(n)

export function foo6<T extends ESValue>(a: ESValue[]): ESValue {
    return a;
}

export function foo7<T extends t3>(a: t3[]): t3 {
    return a;
}

export function foo8<T extends ESValue[]>(a: ESValue[]): ESValue {
    return a;
}

export function foo9<T extends t3[]>(a: t3[]): t3 {
    return a;
}

export class Cls<T extends ESValue> {}

interface CL extends ESValue {}

export interface CLS extends ESValue {}

foo2({ k: 'k', h: {t: 1}}) // we can assign anything to the esobject, even untyped literal
let q1: ESValue = 1; // CTE - ``ESValue`` typed variable can only be local
let q2: ESValue = fooOh(); // CTE - ``ESValue`` typed variable can only be local
let q3: ESValue = q2; // CTE - ``ESValue`` typed variable can only be local
function f() {
    let e1 = fooOh(); // CTE - type of e1 is `any`
    let e2: ESValue = 1; // CTE - can't initialize ESValue with not dynamic values
    let e3: ESValue = {}; // CTE - can't initialize ESValue with not dynamic values
    let e4: ESValue = []; // CTE - can't initialize ESValue with not dynamic values
    let e5: ESValue = ""; // CTE - can't initialize ESValue with not dynamic values
    let e6: ESValue = fooOh(); // OK - explicitly annotaded as ESValue
    let e7: ESValue = e6; // OK - initialize ESValue with ESValue
    e6['prop'] // CTE - can't access dynamic properties of ESValue
    e6[1] // CTE - can't access dynamic properties of ESValue
    e6.prop // CTE - can't access dynamic properties of ESValue
    barOh(e6) // OK - ESValue is passed to interop call
    e6 = e7 // OK - ESValue is assigned to ESValue
}
