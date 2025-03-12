/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

function test(t: boolean): boolean | long[] {
  if (t) {
    return true
  }
  let c: long[] = [4, 6]
  return c
}
function test1(t: int): Object | null {
  if (t) {
    return new Object();
  }
  return null
}
function test2(t: int): Object | undefined {
  if (!t) {
    return new Object();
  }
  return undefined
}

enum Color { Red, Green, Blue }

function main() {
  // for identifiers
  // ---------------
  // ids with numbers (primitive, boxed and objects)

  let x00: boolean
  let x01: byte
  let x02: char
  let x03: short
  let x04: int
  let x05: long
  let x06: float
  let x07: double
  let x08: bigint
  assertEQ(typeof x00, "boolean")
  assertEQ(typeof x01, "number")
  assertEQ(typeof x02, "number")
  assertEQ(typeof x03, "number")
  assertEQ(typeof x04, "number")
  assertEQ(typeof x05, "number")
  assertEQ(typeof x06, "number")
  assertEQ(typeof x07, "number")
  assertEQ(typeof x08, "bigint")

  let x000: Boolean
  let x001: Byte
  let x002: Char
  let x003: Short
  let x004: Int
  let x005: Long
  let x006: Float
  let x007: Double
  let x008: BigInt
  assertEQ(typeof x000, "boolean")
  assertEQ(typeof x001, "number")
  assertEQ(typeof x002, "number")
  assertEQ(typeof x003, "number")
  assertEQ(typeof x004, "number")
  assertEQ(typeof x005, "number")
  assertEQ(typeof x006, "number")
  assertEQ(typeof x007, "number")
  assertEQ(typeof x008, "bigint")

  let x0 = new Boolean()
  let x1 = new Byte()
  let x2 = new Char()
  let x3 = new Short()
  let x4 = new Int()
  let x5 = new Long()
  let x6 = new Float()
  let x7 = new Double()
  let x8 = new BigInt()
  assertEQ(typeof x0, "boolean")
  assertEQ(typeof x1, "number")
  assertEQ(typeof x2, "number")
  assertEQ(typeof x3, "number")
  assertEQ(typeof x4, "number")
  assertEQ(typeof x5, "number")
  assertEQ(typeof x6, "number")
  assertEQ(typeof x7, "number")
  assertEQ(typeof x8, "bigint")

  // ---------------
  // ids with literals

  let l0 = "123"
  let l1 = null
  let l2 = undefined
  let l3 = true
  let l4 = false
  assertEQ(typeof l0, "string")
  assertEQ(typeof l1, "object")
  assertEQ(typeof l2, "undefined")
  assertEQ(typeof l3, "boolean")
  assertEQ(typeof l4, "boolean")

  // ---------------
  // ids with objects and enums

  let o0 = new String("1")
  let o1: Int[] = [1, 2]
  let o2 = test(true)
  let o3 = test(false)
  let o4: Object | null = test1(1)
  let o5: Object | null = test1(0)
  let o6: Object | undefined = test2(1)
  let o7: Object | undefined = test2(0)
  let o8: (a: boolean) => boolean | long[] = test
  assertEQ(typeof o0, "string")
  assertEQ(typeof o1, "object")
  assertEQ(typeof o2, "boolean")
  assertEQ(typeof o3, "object")
  assertEQ(typeof o4, "object")
  assertEQ(typeof o5, "object")
  assertEQ(typeof o6, "undefined")
  assertEQ(typeof o7, "object")
  assertEQ(typeof o8, "function")

  let e0 = Color.Red
  let e1: Color
  assertEQ(typeof e0, "number")
  assertEQ(typeof e1, "number")

  // ===============
  // for expressions
  // ---------------
  // exprs with numbers (objects)

  assertEQ(typeof new Boolean(), "boolean")
  assertEQ(typeof new Byte(), "number")
  assertEQ(typeof new Char(), "number")
  assertEQ(typeof new Short(), "number")
  assertEQ(typeof new Int(), "number")
  assertEQ(typeof new Long(), "number")
  assertEQ(typeof new Float(), "number")
  assertEQ(typeof new Number(), "number")
  assertEQ(typeof new BigInt(), "bigint")

  // ---------------
  // exprs with literals
  assertEQ(typeof "123", "string")
  assertEQ(typeof null, "object")
  assertEQ(typeof undefined, "undefined")
  assertEQ(typeof true, "boolean")
  assertEQ(typeof false, "boolean")
  assertEQ(typeof 1n, "bigint")

  // ---------------
  // exprs with objects and enums
  assertEQ(typeof new String(), "string")
  assertEQ(typeof [1, 2], "object")
  assertEQ(typeof test(true), "boolean")
  assertEQ(typeof test(false), "object")
  assertEQ(typeof test1(1), "object")
  assertEQ(typeof test1(0), "object")
  assertEQ(typeof test2(1), "undefined")
  assertEQ(typeof test1(0), "object")
  assertEQ(typeof ("123" + "124"), "string")
  x004 = 9
  x4 = 6
  assertEQ(typeof (x4 + x004), "number")
  x8 = 1n
  x08 = new BigInt(10)
  assertEQ(typeof (x8 + x08), "bigint")
}
