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

class A {
    a: number = -11;
    tuple: [number, string, boolean] = [1, 'hi', true]
    arrs: [[number, number, boolean], [boolean, number, boolean]] = [
        [1, 3.14, true], this.cc()
    ]
    val: (number|string|boolean) [] = new A().tuple
    A() {
        const tuple2: [string, number, boolean] = ['s', 3.14, true]
        let array2: (string | number | boolean)[] = tuple2

    }
    aa(): number {
        let ss: number[] = [-1, -5]
        return ss[0];
    }
    cc(): [boolean, number, boolean] {
        return [true, 33, false];
    }
    dd(): [boolean, string, A] {
        return [true, 'hello', new A()];
    }
    ee() {
        let ccVal: (boolean | number | boolean)[] = this.cc()
        return ccVal;
    }

    ff() {
        let array = tuple;
        return array;
    }
    gg() {
        return this.arrs[0];
    }
}

function test2() {
    const tuple3: [string, number, boolean] = ['s', 3.14, true]
    return tuple3;
}
function test3() {
    let obj: A = new A()
    return obj.dd();
}

let a: A = new A()

const tuple: [number, number, boolean] = [1, 3.14, true]
const tuple1: [number, string, boolean] = [1, '3.14', true]
const array: (number | boolean)[] = tuple
const tuple2: [string, number, boolean] = ['s', 3.14, true]
const array1: (number | string | boolean)[] = tuple1
const array2: (string | number | boolean)[] = tuple2

let tt: (string | number | boolean)[] = this.test2()
let gg: (boolean | number | boolean)[] = new A().ee()
let ff = new A().ff()
let hh: (boolean | number | boolean)[] =ff
let mm: (boolean | number | boolean)[] = a.gg();
let test: (boolean | string | A)[] = this.test3()