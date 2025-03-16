/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

let o1 = {n: 42, s: "foo"}
let o2: Object = {n: 42, s: "foo"}
let o3: object = {n: 42, s: "foo"}

let oo: Object[] = [{n: 1, s: "1"}, {n: 2, s: "2"}]

class C2 {
    s: string
    constructor(s: string) {
        this.s = "s =" + s
    }
}
let o4: C2 = {s: "foo"}

class C3 {
    readonly n: number = 0
    readonly s: string = ""
}
let o5: C3 = {n: 42, s: "foo"}

abstract class A {}
let o6: A = {}

class C4 {
    n: number = 0
    s: string = ""
    f() {
        console.log("Hello")
    }
}
let o7: C4 = {n: 42, s: "foo", f : () => {}}

class Point {
    x: number = 0
    y: number = 0
}
function id_x_y(o: Point): Point {
    return o
}

// Structural typing is used to deduce that p is Point:
let p = {x: 5, y: 10}
id_x_y(p)

// A literal can be contextually (i.e., implicitly) typed as Point:
id_x_y({x: 5, y: 10})