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

abstract class A {
    str: string = "A"
}

abstract class B extends A {
    public get_str(): string {
        return this.str;
    }

    public get_super_str(): string {
        return super.str;
    }
}

class BB extends B {}

abstract class C extends B {
    str: string = "C"

    public override get_str(): string {
        return this.str;
    }

    public override get_super_str(): string {
        return super.str;
    }
}

class CC extends C {}

function main(): void {
  let b: B = new BB();
  let c: C = new CC();

  assert(b.str == "A")
  assert(b.get_str() == "A")
  assert(b.get_super_str() == "A")
  assert(c.str == "C")
  assert(c.get_str() == "C")
  assert(c.get_super_str() == "A")

  assert((b as B).str == "A")
  assert((b as A).str == "A")
  assert((b as B).get_str() == "A")
  assert((b as B).get_super_str() == "A")

  assert((c as C).str == "C")
  assert((c as B).str == "A")
  assert((c as A).str == "A")

  assert((c as C).get_str() == "C")
  assert((c as C).get_super_str() == "A")
  assert((c as B).get_str() == "C")
  assert((c as B).get_super_str() == "A")
}
