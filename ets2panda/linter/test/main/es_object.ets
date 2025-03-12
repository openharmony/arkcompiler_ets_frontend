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
type ESObject = any

class A<T> {}

let g1: ESObject
let g2: ESObject[]
let g3: A<ESObject>

class B {
    f1: ESObject
    f2: ESObject[]
    f3: A<ESObject>

    constructor(p1: ESObject, p2: ESObject[], p3: A<ESObject>) {
        this.f1 = p1
        this.f2 = p2
        this.f3 = p3
    }

    foo1(p1: ESObject, p2: ESObject[], p3: A<ESObject>): ESObject {
        return p1
    }

    foo2(p1: ESObject, p2: ESObject[], p3: A<ESObject>): ESObject[] {
        return p2
    }

    foo3(p1: ESObject, p2: ESObject[], p3: A<ESObject>): A<ESObject> {
        return p3
    }
}

function bar1(p1: ESObject, p2: ESObject[], p3: A<ESObject>): ESObject {
    return p1
}

function bar2(p1: ESObject, p2: ESObject[], p3: A<ESObject>): ESObject[] {
    return p2
}

function bar3(p1: ESObject, p2: ESObject[], p3: A<ESObject>): A<ESObject> {
    return p3
}

function ff(): {x: number} {
    return {x: 10}
}

function baz(p1: ESObject, p2: ESObject[], p3: A<ESObject>): void {
    const c1: ESObject = p1;
    const c2: ESObject[] = p2
    const c3: A<ESObject> = p3

    let v1: ESObject = p1
    let v2: ESObject[] = p2
    let v3: A<ESObject> = p3

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

    let v11: ESObject = {}
    let v12: ESObject = "abc"
    let v13: ESObject = ff()
    let v14: ESObject = [1, 2]
    let v15: ESObject = [p1, c1]
    let v16: ESObject = [p1, c1, "abc"]
    let v17: ESObject = new A<string>()

    let n1: number = v1
    n1 = v1
    let n2: number = p1 as number
}

export let obj = new ESObject();

type t1 = ESObject
type t2 = ESObject[]

export type t3 = ESObject
export type t4 = ESObject[]

export type t5 = t3
export type t6 = t4[]

export function foo1(): any {
    let a: ESObject = "STRING";
    return a
}

export function foo2(a: ESObject): ESObject {
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

export function foo4(a: ESObject[]): ESObject {
    return a;
}

export function foo5(a: t3[]): t3 {
    return a;
}

foo4([2, 3])
foo5([2, 3])
foo4(["str1", "str2"])
foo5(["str1", "str2"])
let n: ESObject
n = null

foo4(n)
foo5(n)

export function foo6<T extends ESObject>(a: ESObject[]): ESObject {
    return a;
}

export function foo7<T extends t3>(a: t3[]): t3 {
    return a;
}

export function foo8<T extends ESObject[]>(a: ESObject[]): ESObject {
    return a;
}

export function foo9<T extends t3[]>(a: t3[]): t3 {
    return a;
}

export class Cls<T extends ESObject> {}

interface CL extends ESObject {}

export interface CLS extends ESObject {}

foo2({ k: 'k', h: {t: 1}}) // we can assign anything to the esobject, even untyped literal
let q1: ESObject = 1; // CTE - ``ESObject`` typed variable can only be local
let q2: ESObject = fooOh(); // CTE - ``ESObject`` typed variable can only be local
let q3: ESObject = q2; // CTE - ``ESObject`` typed variable can only be local
function f() {
    let e1 = fooOh(); // CTE - type of e1 is `any`
    let e2: ESObject = 1; // CTE - can't initialize ESObject with not dynamic values
    let e3: ESObject = {}; // CTE - can't initialize ESObject with not dynamic values
    let e4: ESObject = []; // CTE - can't initialize ESObject with not dynamic values
    let e5: ESObject = ""; // CTE - can't initialize ESObject with not dynamic values
    let e6: ESObject = fooOh(); // OK - explicitly annotaded as ESObject
    let e7: ESObject = e6; // OK - initialize ESObject with ESObject
    e6['prop'] // CTE - can't access dynamic properties of ESObject
    e6[1] // CTE - can't access dynamic properties of ESObject
    e6.prop // CTE - can't access dynamic properties of ESObject
    barOh(e6) // OK - ESObject is passed to interop call
    e6 = e7 // OK - ESObject is assigned to ESObject
}
