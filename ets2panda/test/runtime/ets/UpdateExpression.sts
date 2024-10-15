/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
    assert a == 11;
    assert b == 11;

    assert ++a == 12;
    assert a == 12;
    assert b == 11;
  }

  {
    let a: int = 20;
    let b = a++;
    assert a == 21;
    assert b == 20;

    assert a++ == 21;
    assert a == 22;
    assert b == 20;
  }

  {
    let a: Double = new Double(30.0);
    let b = ++a;
    assert a == 31.0;
    assert a.doubleValue() == 31.0;
    assert b == 31.0;
    assert b.doubleValue() == 31.0;

    assert (++a).doubleValue() == 32.0;
    assert a == 32.0;
    assert a.doubleValue() == 32.0;
    assert b == 31.0;
    assert b.doubleValue() == 31.0;
  }

  {
    let a: Int = new Int(40);
    let b = a++;
    assert a == 41;
    assert a.intValue() == 41;
    assert b == 40;
    assert b.intValue() == 40;

    assert (a++).intValue() == 41;
    assert a == 42;
    assert a.intValue() == 42;
    assert b == 40;
    assert b.intValue() == 40;
  }

  {
    let fn: (x: Int) => Int = (x: Int): Int => { return x; };
    let a: Int = new Int(50);
    let b = fn(a++);
    assert a == 51;
    assert a.intValue() == 51;
    assert b == 50;
    assert b.intValue() == 50;

    assert fn(++a) == 52;
    assert a == 52;
  }

  {
    let b: byte = 127;
    assert ++b as int == -128;
    assert --b as int == 127;

    let c: char = 65535;
    assert ++c as int == 0;
    assert --c as int == 65535;

    let s: short = 32767;
    assert ++s as int == -32768;
    assert --s as int == 32767;
  }

  {
    let b: Int[] = [1, 2]
    assert ++b[1] == 3
    assert --b[1] == 2
  }
}
