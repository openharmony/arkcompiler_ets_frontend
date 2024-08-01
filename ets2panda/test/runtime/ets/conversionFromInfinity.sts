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


function main(): void {

let nan_byte = Infinity * 0 as byte 
let nan_short = Infinity * 0 as short
let nan_long = Infinity * 0 as long
let nan_char = Infinity * 0 as char
let nan_int = Infinity * 0 as int
let nan_float = Infinity * 0 as float 
let nan_double = Infinity * 0 as double
let nan_byte2 = Infinity * 0 as byte 

assert(nan_byte == 0)
assert(nan_int == 0)
assert(nan_short == 0)
assert(nan_long == 0)
assert(nan_char == 0)
assert(isNaN(nan_float))
assert(isNaN(nan_double))
assert(nan_byte2 == 0)

let b1 = Infinity as byte // converted at compile time, as 'Infinity' is constant
let b2: double = Infinity
let b3 = b2 as byte // converted in runtime, as b2 isn't constant

assert(b1 == -1)
assert(b3 == -1)

let l1 = Infinity as long
let l2: double = Infinity
let l3 = l2 as long
let l4 = -Infinity as long

assert(l1 == 9223372036854775807)
assert(l3 == 9223372036854775807)
assert(l4 == -9223372036854775808)

let i1 = Infinity as int
let i2: double = Infinity
let i3 = i2 as int
let i4 = -Infinity as int

assert(i1 == 2147483647)
assert(i3 == 2147483647)
assert(i4 == -2147483648)

let s1 = Infinity as short
let s2: double = Infinity
let s3 = s2 as short
let s4 = -Infinity as short

assert(s1 == -1)
assert(s3 == -1)
assert(s4 == 0)

let c1 = Infinity as char
let c2: double = Infinity
let c3 = c2 as char
let c4 = -Infinity as char

assert(c1 == 65535)
assert(c3 == 65535)
assert(c4 == 0)

let f1 = Infinity as float
let f2: double = Infinity
let f3 = f2 as float
let f4 = -Infinity as float

assert(f1 == Infinity)
assert(f3 == Infinity)
assert(f4 == -Infinity)

let d1 = Infinity as double
let d2: double = Infinity
let d3 = d2 as double
let d4 = -Infinity as double

assert(d1 == Infinity)
assert(d3 == Infinity)
assert(d4 == -Infinity)
}
