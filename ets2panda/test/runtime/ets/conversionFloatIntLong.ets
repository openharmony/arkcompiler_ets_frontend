/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License")
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

function joinSpread(first: double, ...rest: double[]): double[] {
    let res = new double[rest.length + 1]
    let i = 0
    res[i] = first
    i++
    for (let it of rest) {
        res[i] = it
        i++
    }
    return res;
}

function bar(a: int, b: int, c: int) {
    let res = joinSpread(a, b, c)
    assert(res.length == 3)
    assert(res[0] == a)
    assert(res[1] == b)
    assert(res[2] == c)
}

function first(...values: number[]): number {
    return values[0]
}

function foo(a: int, b: int) {
    return first(a, b)
}

function main(): void {

    let f: float =  1000000001.044
    let f_i = f as int
    let f_l = f as long
    assert(f_l == 1000000000)
    assert(f_i == 1000000000)

    let d: double =  1000000001.044
    let d_i = d as int
    let d_l = d as long
    assert(d_l == 1000000001)
    assert(d_i == 1000000001)

    let f2: float=  10001.044
    let f_i2 = f2 as int
    let f_l2 = f2 as long
    assert(f_l2 == 10001)
    assert(f_i2 == 10001)

    let i: int =  2147483647
    let i_f = i as float
    let i_d = i as double
    assert(i_f == 2147483600)
    assert(i_d == 2147483647)

    let i2: int =  1073741824
    let i_f2 = i2 as float
    let i_d2 = i2 as double
    assert(i_f2 == 1073741824)
    assert(i_d2 == 1073741824)

    let l: long=  1073741824
    let l_f = l as float
    let d_f = l as double
    assert(l_f == 1073741824)
    assert(d_f == 1073741824)

    let l2: int =  2147483647
    let l_f2 = l2 as float
    let d_f2 = l2 as double
    assert(l_f2 == 2147483600)
    assert(d_f2 == 2147483647)

    bar(314, 27182, 2)
    assert(foo(2, 1) == 2)
}
