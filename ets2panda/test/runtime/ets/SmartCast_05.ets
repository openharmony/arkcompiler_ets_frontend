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

class C  {
  readonly a: boolean
  constructor(a_: boolean = false) {
    this.a = a_;
  }
}

function foo1(x: C|null|undefined): string {
  if (x == null || !x.a)  {
    return x != null ? "false1" : "null"; 
  } else  {
    return x.a ? "true2" : "false2";
  }
}

function foo2(x: C|null|undefined): string {
  if (x != null && x.a)  {
    return "true";
  } else  {
    return  x != null ? "false" : "null";
  }
}

function bar(x: C|null|undefined, y: boolean, z: boolean): string {
  if ((x instanceof C && y) || (x instanceof C && z))  {
    return (x.a ? "true1" : "false1") + y + z;
  } else  {
    return (x != null ? (x.a ? "true2" : "false2") : "null") + y + z;
  }
}

function main(): void {
  assertEQ(foo1(null), "null")
  assertEQ(foo2(null), "null")
  assertEQ(bar(null, true, true), "nulltruetrue")
  assertEQ(bar(null, true, false), "nulltruefalse")
  assertEQ(bar(null, false, true), "nullfalsetrue")
  assertEQ(bar(null, false, false), "nullfalsefalse")

  assertEQ(foo1(undefined), "null")
  assertEQ(foo2(undefined), "null")
  assertEQ(bar(undefined, true, true), "nulltruetrue")
  assertEQ(bar(undefined, true, false), "nulltruefalse")
  assertEQ(bar(undefined, false, true), "nullfalsetrue")
  assertEQ(bar(undefined, false, false), "nullfalsefalse")

  let c = new C();
  assertEQ(foo1(c), "false1")
  assertEQ(foo2(c), "false")
  assertEQ(bar(c, true, true), "false1truetrue")
  assertEQ(bar(c, true, false), "false1truefalse")
  assertEQ(bar(c, false, true), "false1falsetrue")
  assertEQ(bar(c, false, false), "false2falsefalse")

  c = new C(true);
  assertEQ(foo1(c), "true2")
  assertEQ(foo2(c), "true")
  assertEQ(bar(c, true, true), "true1truetrue")
  assertEQ(bar(c, true, false), "true1truefalse")
  assertEQ(bar(c, false, true), "true1falsetrue")
  assertEQ(bar(c, false, false), "true2falsefalse")
}
