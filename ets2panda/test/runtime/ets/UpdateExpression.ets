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
  {
    let a: byte = 10;
    let b = ++a;
    assertEQ(a, 11)
    assertEQ(b, 11)

    assertEQ(++a, 12)
    assertEQ(a, 12)
    assertEQ(b, 11)
  }

  {
    let a: int = 20;
    let b = a++;
    assertEQ(a, 21)
    assertEQ(b, 20)

    assertEQ(a++, 21)
    assertEQ(a, 22)
    assertEQ(b, 20)
  }

  {
    let a: Double = new Double(30.0);
    let b = ++a;
    assertEQ(a, 31.0)
    assertEQ(a.toDouble(), 31.0)
    assertEQ(b, 31.0)
    assertEQ(b.toDouble(), 31.0)

    assertEQ((++a).toDouble(), 32.0)
    assertEQ(a, 32.0)
    assertEQ(a.toDouble(), 32.0)
    assertEQ(b, 31.0)
    assertEQ(b.toDouble(), 31.0)
  }

  {
    let a: Int = new Int(40);
    let b = a++;
    assertEQ(a, 41)
    assertEQ(a.toInt(), 41)
    assertEQ(b, 40)
    assertEQ(b.toInt(), 40)

    assertEQ((a++).toInt(), 41)
    assertEQ(a, 42)
    assertEQ(a.toInt(), 42)
    assertEQ(b, 40)
    assertEQ(b.toInt(), 40)
  }

  {
    let fn: (x: Int) => Int = (x: Int): Int => { return x; };
    let a: Int = new Int(50);
    let b = fn(a++);
    assertEQ(a, 51)
    assertEQ(a.toInt(), 51)
    assertEQ(b, 50)
    assertEQ(b.toInt(), 50)

    assertEQ(fn(++a), 52)
    assertEQ(a, 52)
  }

  {
    let b: byte = 127;
    assertEQ(++b as int, -128)
    assertEQ(--b as int, 127)

    let c: char = 65535;
    assertEQ(++c as int, 0)
    assertEQ(--c as int, 65535)

    let s: short = 32767;
    assertEQ(++s as int, -32768)
    assertEQ(--s as int, 32767)
  }

  {
    let b: Int[] = [1, 2]
    assertEQ(++b[1], 3)
    assertEQ(--b[1], 2)
  }
}
