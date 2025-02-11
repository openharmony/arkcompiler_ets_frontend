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
  assertEQ(a as float, 2147483648)  // rounded
  assertEQ(a as long, 2147483649)
  assertEQ(a as int, 2147483647  )  // 2^31 - 1 == MAX_INT == 0xFFFFFFFF
  assertEQ(a as short, -1         ) // 0xFFFF
  assertEQ(a as char, c'\uFFFF')
  assertEQ(a as byte, -1           )// 0xFF

  a = -2147483649.0                 // 2^31 + 1
  assertEQ(a as float, -2147483648) // rounded
  assertEQ(a as long, -2147483649)
  assertEQ(a as int, -2147483648)   // -2^31 == MIN_INT == 0x10000000
  assertEQ(a as short, 0)
  assertEQ(a as char, c'\u0000')
  assertEQ(a as byte, 0)

  let b : float = 70000.9921875;
  assertEQ(b as double, 70000.9921875)
  assertEQ(b as long, 70000  )         // rounded, 70000 == 0x11170
  assertEQ(b as int, 70000)
  assertEQ(b as short, 4464)           // 4464 == 0x1170
  assertEQ(b as char, c'\u1170')
  assertEQ(b as byte, 112)             // 112 == 0x70

  let c : long = 1193046;              // 1193046 == 0x123456
  assertEQ(c as int, 1193046)
  assertEQ(c as short, 13398)          // 13398 == 0x3456
  assertEQ(c as char, c'\u3456')
  assertEQ(c as byte, 86)              // 86 == 0x56

  let d : int = 126977;                // 65537 == 0x1F001
  assertEQ(d as short, -4095)          // -4095 == 0xF001
  assertEQ(d as char, c'\uF001')
  assertEQ(d as byte, 1)               // 1 == 0x01

  let e : short = -30875;              // -30875 == 0x8765
  assertEQ(e as double, -30875.0)
  assertEQ(e as float, -30875.0)
  assertEQ(e as long, -30875)          // -30875 == 0xFFFFFFFFFFFF8765
  assertEQ(e as int, -30875)           // -30875 == 0xFFFF8765
  assertEQ(e as char, c'\u8765')
  assertEQ(e as byte, 101)             // 101 == 0x65

  let f : char = c'\uF001';
  assertEQ(f as double, 61441.0)
  assertEQ(f as float, 61441.0)
  assertEQ(f as long, 61441)            // 61441 == 0x000000000000F001
  assertEQ(f as int, 61441)             // 61441 == 0x0000F001
  assertEQ(f as short, 0xf001 as short) // -4095 == 0xF001
  assertEQ(f as short, -4095)

  let g : byte = -128;
  assertEQ(g as double, -128.0)
  assertEQ(g as float, -128.0)
  assertEQ(g as long, -128)
  assertEQ(g as int, -128)
  assertEQ(g as short, -128)
  assertEQ(g as char, c'\uFF80')
  assertEQ((-128) as byte, -128)
  assertEQ((-129) as byte, 127)

  let i : boolean = true;
  assertEQ(i as boolean, true)

  i = false;
  assertEQ(i as boolean, false)

  assertEQ(4294967296.0 as byte, -1)
  assertEQ(4294967296.0 as char, c'\uFFFF')
  assertEQ(4294967296.0 as short, -1)
  assertEQ(4294967296.0 as int, Int.MAX_VALUE)
  assertEQ(4294967296.0 as long, 4294967296)
  assertEQ(-4294967296.0 as byte, 0)
  assertEQ(-4294967296.0 as char, c'\u0000')
  assertEQ(-4294967296.0 as short, 0)
  assertEQ(-4294967296.0 as int, Int.MIN_VALUE)
  assertEQ(-4294967296.0 as long, -4294967296)

  return;
}
