/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
  let a : double = 2147483649.0;    // 2^31 + 1
  assertEQ(Double.toFloat(a), 2147483648)  // rounded
  assertEQ(Double.toLong(a), 2147483649)
  assertEQ(Double.toInt(a), 2147483647  )  // 2^31 - 1 == MAX_INT == 0xFFFFFFFF
  assertEQ(Double.toShort(a), -1         ) // 0xFFFF
  assertEQ(Double.toChar(a), c'\uFFFF')
  assertEQ(Double.toByte(a), -1           )// 0xFF

  a = -2147483649.0                 // 2^31 + 1
  assertEQ(Double.toFloat(a), -2147483648) // rounded
  assertEQ(Double.toLong(a), -2147483649)
  assertEQ(Double.toInt(a), -2147483648)   // -2^31 == MIN_INT == 0x10000000
  assertEQ(Double.toShort(a), 0)
  assertEQ(Double.toChar(a), c'\u0000')
  assertEQ(Double.toByte(a), 0)

  let b : float = 70000.9921875f;
  assertEQ(Float.toDouble(b), 70000.9921875)
  assertEQ(Float.toLong(b), 70000  )         // rounded, 70000 == 0x11170
  assertEQ(Float.toInt(b), 70000)
  assertEQ(Float.toShort(b), 4464)           // 4464 == 0x1170
  assertEQ(Float.toChar(b), c'\u1170')
  assertEQ(Float.toByte(b), 112)             // 112 == 0x70

  let c : long = 1193046;              // 1193046 == 0x123456
  assertEQ(Long.toInt(c), 1193046)
  assertEQ(Long.toShort(c), 13398)          // 13398 == 0x3456
  assertEQ(Long.toChar(c), c'\u3456')
  assertEQ(Long.toByte(c), 86)              // 86 == 0x56

  let d : int = 126977;                // 65537 == 0x1F001
  assertEQ(Int.toShort(d), -4095)          // -4095 == 0xF001
  assertEQ(Int.toChar(d), c'\uF001')
  assertEQ(Int.toByte(d), 1)               // 1 == 0x01

  let e : short = -30875;              // -30875 == 0x8765
  assertEQ(Short.toDouble(e), -30875.0)
  assertEQ(Short.toFloat(e), -30875.0)
  assertEQ(Short.toLong(e), -30875)          // -30875 == 0xFFFFFFFFFFFF8765
  assertEQ(Short.toInt(e), -30875)           // -30875 == 0xFFFF8765
  assertEQ(Short.toChar(e), c'\u8765')
  assertEQ(Short.toByte(e), 101)             // 101 == 0x65

  let f : char = c'\uF001';
  assertEQ(Char.toDouble(f), 61441.0)
  assertEQ(Char.toFloat(f), 61441.0)
  assertEQ(Char.toLong(f), 61441)            // 61441 == 0x000000000000F001
  assertEQ(Char.toInt(f), 61441)             // 61441 == 0x0000F001
  assertEQ(Char.toShort(f), 0xf001 as short) // -4095 == 0xF001
  assertEQ(Char.toShort(f), -4095)

  let g : byte = -128;
  assertEQ(Byte.toDouble(g), -128.0)
  assertEQ(Byte.toFloat(g), -128.0)
  assertEQ(Byte.toLong(g), -128)
  assertEQ(Byte.toInt(g), -128)
  assertEQ(Byte.toShort(g), -128)
  assertEQ(Byte.toChar(g), c'\uFF80')
  assertEQ(Int.toByte(-128), -128)
  assertEQ(Int.toByte(-129), 127)

  let i : boolean = true;
  assertEQ(i, true)

  i = false;
  assertEQ(i, false)

  assertEQ(Double.toByte(4294967296.0), -1)
  assertEQ(Double.toChar(4294967296.0), c'\uFFFF')
  assertEQ(Double.toShort(4294967296.0), -1)
  assertEQ(Double.toInt(4294967296.0), Int.MAX_VALUE)
  assertEQ(Double.toLong(4294967296.0), 4294967296)
  assertEQ(Double.toByte(-4294967296.0), 0)
  assertEQ(Double.toChar(-4294967296.0), c'\u0000')
  assertEQ(Double.toShort(-4294967296.0), 0)
  assertEQ(Double.toInt(-4294967296.0), Int.MIN_VALUE)
  assertEQ(Double.toLong(-4294967296.0), -4294967296)

  return;
}
