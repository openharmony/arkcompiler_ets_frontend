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

let global_boolean_: boolean = new Boolean(true);
let global_byte_: byte = new Byte(20 as byte);
let global_char_: char = new Char(c'a');
let global_double_: double = new Double(1.797+308);
let global_float_: float = new Float(2.22 as float);
let global_int_: int = new Int(200000);
let global_long_: long = new Long(200000000000);
let global_short_: short = new Short(20 as short);

class A {
  public boolean_: boolean = new Boolean(true);
  public byte_: byte = new Byte(20 as byte);
  public char_: char = new Char(c'a');
  public double_: double = new Double(1.797+308);
  public float_: float = new Float(2.22 as float);
  public int_: int = new Int(200000);
  public long_: long = new Long(200000000000);
  public short_: short = new Short(20 as short);
}

function main() {
  assertEQ(global_boolean_, true)
  assertEQ(global_byte_, 20)
  assertEQ(global_char_, c'a')
  assertEQ(global_double_, 1.797+308)
  assertEQ(global_float_, 2.22 as float)
  assertEQ(global_int_, 200000)
  assertEQ(global_long_, 200000000000)
  assertEQ(global_short_, 20)

  let a = new A();
  assertEQ(a.boolean_, true)
  assertEQ(a.byte_, 20)
  assertEQ(a.char_, c'a')
  assertEQ(a.double_, 1.797+308)
  assertEQ(a.float_, 2.22 as float)
  assertEQ(a.int_, 200000)
  assertEQ(a.long_, 200000000000)
  assertEQ(a.short_, 20)
}
