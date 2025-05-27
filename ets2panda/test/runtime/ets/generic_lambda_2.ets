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

function main() {
    let foo = <T, U> (p: T, q: U): [T, U] => [p, q]

    // Explicitly deducing generics
    let res1 = foo<number, string>(1.0, "abc")
    assertEQ(res1[0], 1.0)
    assertEQ(res1[1], "abc")

    let res2 = foo<Error, null>(new Error(), null)
    assertTrue(res2[0] instanceof Error)
    assertEQ(res2[1], null)

    let res3 = foo<[Double, string], [Error, null]>(res1, res2)
    assertEQ(res3[0][0], 1.0)
    assertEQ(res3[0][1], "abc")
    assertTrue(res3[1][0] instanceof Error)
    assertEQ(res3[1][1], null)

    // Implicit derivation of generics
    let res4 = foo(1.0, "abc")
    assertEQ(res4[0], 1.0)
    assertEQ(res4[1], "abc")

    let res5 = foo(new Error(), null)
    assertTrue(res5[0] instanceof Error)
    assertEQ(res5[1], null)

    let res6 = foo(res1, res2)
    assertEQ(res6[0][0], 1.0)
    assertEQ(res6[0][1], "abc")
    assertTrue(res6[1][0] instanceof Error)
    assertEQ(res6[1][1], null)
}
