/*
 * Copyright (c) 2023 - 2024-2025 Huawei Device Co., Ltd.
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

class A {
  static static_name: char = c'A';
  name: char = c'A';

  final get_name_a(): char {
    return this.name;
  }

  get_name(): char {
    return this.name;
  }

  static get_static_name(): char {
    return A.static_name;
  }
}

class B extends A {
  static static_name: char = c'B';
  name: char = c'B';

  static get_static_name(): char {
    return B.static_name;
  }

  override get_name(): char {
    return this.name;
  }

  super_name(): char {
    return super.get_name();
  }
}

final class C extends B {
  static static_name: char = c'C';
  name: char = c'C';

  static get_static_name(): char {
    return C.static_name;
  }

  override get_name(): char {
    return this.name;
  }

  override super_name(): char {
    return super.get_name();
  }
}

function main() : void {
  {
    let a = new A();
    assertEQ(A.static_name, c'A')
    assertEQ(A.get_static_name(), c'A')
    assertEQ(a.name, c'A')
    assertEQ(a.get_name(), c'A')
    assertEQ(a.get_name_a(), c'A')
  }

  {
    let b = new B();
    assertEQ(B.static_name, c'B')
    assertEQ(B.get_static_name(), c'B')
    assertEQ(b.name, c'B')
    assertEQ(b.get_name(), c'B')
    assertEQ(b.super_name(), c'A')
    assertEQ(b.get_name_a(), c'A')
  }

  {
    let b_as_a: A = new B();
    assertEQ(b_as_a.name, c'B')
    assertEQ(b_as_a.get_name(), c'B')
    assertEQ(b_as_a.get_name_a(), c'A')
  }

  {
    let c = new C();
    assertEQ(C.static_name, c'C')
    assertEQ(C.get_static_name(), c'C')
    assertEQ(c.name, c'C')
    assertEQ(c.get_name(), c'C')
    assertEQ(c.super_name(), c'B')
    assertEQ(c.get_name_a(), c'A')
  }

  {
    let c_as_a: A = new C();
    assertEQ(c_as_a.name, c'C')
    assertEQ(c_as_a.get_name(), c'C')
    assertEQ(c_as_a.get_name_a(), c'A')
  }

  {
    let c_as_b: B = new C();
    assertEQ(c_as_b.name, c'C')
    assertEQ(c_as_b.get_name(), c'C')
    assertEQ(c_as_b.super_name(), c'B')
    assertEQ(c_as_b.get_name_a(), c'A')
  }

  {
    let c = new C();
    assertEQ((c as A).name, c'A')
    assertEQ((c as A).get_name(), c'C')
    assertEQ((c as A).get_name_a(), c'A')
  }

  {
    assertEQ((new C() as B).name, c'B')
    assertTrue((new C() as B).get_name() ==c'C')
    assertEQ((new C() as B).super_name(), c'B')
    assertEQ((new C() as B).get_name_a(), c'A')
  }
}
