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


function foo(a: int): double {
    return a.toDouble() + 10.5;
}

function main() {
    let b: byte = 1
    let c: char = c'a'
    let s: short = 5
    let i: int = 25
    let l: long = 125
    let f: float = 2.71f
    let d: double = 3.14

    // byte
    assertEQ(b.toChar(),  c'\u0001')
    assertEQ(b.toShort(), 1 as short)
    assertEQ(b.toInt(),   1 as int)
    assertEQ(b.toLong(),  1 as long)
    assertEQ(b.toFloat(), 1.0f)
    assertEQ(b.toDouble(),1.0)

    // short
    assertEQ(s.toByte(),  5 as byte)
    assertEQ(s.toChar(),  c'\u0005')
    assertEQ(s.toInt(),   5 as int)
    assertEQ(s.toLong(),  5 as long)
    assertEQ(s.toFloat(), 5.0f)
    assertEQ(s.toDouble(),5.0)

    // int
    assertEQ(i.toByte(),  25 as byte)
    assertEQ(i.toChar(),  c'\u0019')
    assertEQ(i.toShort(), 25 as short)
    assertEQ(i.toLong(),  25 as long)
    assertEQ(i.toFloat(), 25.0f)
    assertEQ(i.toDouble(),25.0)

    assertEQ(foo(i), 35.5)

    // long
    assertEQ(l.toByte(),  125 as byte)
    assertEQ(l.toChar(),  c'\u007d')
    assertEQ(l.toShort(), 125 as short)
    assertEQ(l.toInt(),   125 as int)
    assertEQ(l.toFloat(), 125.0f)
    assertEQ(l.toDouble(),125.0)

    // float
    assertEQ(f.toByte(),  2 as byte)
    assertEQ(f.toShort(), 2 as short)
    assertEQ(f.toInt(),   2 as int)
    assertEQ(f.toLong(),  2.0 as long)
    assertEQ(f.toDouble(),2.71f as double)

    // double
    assertEQ(d.toByte(),  3 as byte)
    assertEQ(d.toShort(), 3 as short)
    assertEQ(d.toInt(),   3 as int)
    assertEQ(d.toLong(),  3.0 as long)
    assertEQ(d.toFloat(), 3.14f)
}
