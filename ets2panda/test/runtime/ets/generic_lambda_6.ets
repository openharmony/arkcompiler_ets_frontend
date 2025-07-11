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


// All testcases are set in top level without function
let foo1 = <T>(p: T): T => p;

// Explicitly deducing generics
arktest.assertEQ(foo1<int>(1), 1)
arktest.assertEQ(foo1<number>(1.5), 1.5)
arktest.assertEQ(foo1<boolean>(false), false)
arktest.assertEQ(foo1<string>("123"), "123")

let foo1res1: [int, string] = foo1<[int, string]>([123, "123"])
arktest.assertEQ(foo1res1[0] as int, 123)
arktest.assertEQ(foo1res1[1] as string, "123")

let foo1res2: int[] = foo1<int[]>([1, 2, 3])
arktest.assertEQ(foo1res2[0], 1)
arktest.assertEQ(foo1res2[1], 2)
arktest.assertEQ(foo1res2[2], 3)

let foo1res3: [[int, string], int[]] = foo1<[[int, string], int[]]>([foo1res1, foo1res2])
arktest.assertEQ(foo1res3[0][0], 123)
arktest.assertEQ(foo1res3[0][1], "123")
arktest.assertEQ(foo1res3[1][0], 1)
arktest.assertEQ(foo1res3[1][1], 2)
arktest.assertEQ(foo1res3[1][2], 3)

let foo1res4: ()=>void = foo1<()=>void>((): void=>{})
foo1res4()

// Implicit derivation of generics
arktest.assertEQ(foo1(1), 1)
arktest.assertEQ(foo1(1.5), 1.5)
arktest.assertEQ(foo1(false), false)
arktest.assertEQ(foo1("123"), "123")

let foo1res5: Array<Int|String> = foo1([123, "123"])
arktest.assertEQ(foo1res5[0] as int, 123)
arktest.assertEQ(foo1res5[1] as string, "123")

let foo1res6: int[] = foo1([1, 2, 3])
arktest.assertEQ(foo1res6[0], 1)
arktest.assertEQ(foo1res6[1], 2)
arktest.assertEQ(foo1res6[2], 3)

let foo = <T, U> (p: T, q: U): [T, U] => [p, q]

// Explicitly deducing generics
let res1 = foo<number, string>(1.0, "abc")
arktest.assertEQ(res1[0], 1.0)
arktest.assertEQ(res1[1], "abc")

let res2 = foo<Error, null>(new Error(), null)
arktest.assertTrue(res2[0] instanceof Error)
arktest.assertEQ(res2[1], null)

let res3 = foo<[Double, string], [Error, null]>(res1, res2)
arktest.assertEQ(res3[0][0], 1.0)
arktest.assertEQ(res3[0][1], "abc")
arktest.assertTrue(res3[1][0] instanceof Error)
arktest.assertEQ(res3[1][1], null)

// Implicit derivation of generics
let res4 = foo(1.0, "abc")
arktest.assertEQ(res4[0], 1.0)
arktest.assertEQ(res4[1], "abc")

let res5 = foo(new Error(), null)
arktest.assertTrue(res5[0] instanceof Error)
arktest.assertEQ(res5[1], null)

let res6 = foo(res1, res2)
arktest.assertEQ(res6[0][0], 1.0)
arktest.assertEQ(res6[0][1], "abc")
arktest.assertTrue(res6[1][0] instanceof Error)
arktest.assertEQ(res6[1][1], null)
