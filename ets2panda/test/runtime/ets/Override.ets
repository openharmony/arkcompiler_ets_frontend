/**
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http: //www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

interface I {
  self(): I;
  fn(): Object;
  fn2(): Object;
  fn3(): Object;
  fn4(): Object;
  fn5(): Object[];
}

class A implements I {
  public x: int = 42;
  override self(): A { return this; }
  override fn(): String { return ""; }
  override fn2(): Object[] { return [new Object()]; }
  override fn3(): int[] { return [0]; }
  override fn4(): int[][] { return [[0]]; }
  override fn5(): String[] { return [""]; }
}


function main(): void {
  let a = new A();
  assert a.self().x == 42;
  assert a.fn() == "";
  assert a.fn2().length == 1;
  assert a.fn3()[0] == 0;
  assert a.fn4()[0][0] == 0;
  assert a.fn5()[0] == "";

  // let i: I = a;
  // assert i.self() instanceof A;
  // assert (i.fn() as String) == "";
  // assert (i.fn2() as Object[])[0] == new Object();
  // assert (i.fn3() as int[])[0] == 0;
  // assert (i.fn4() as String[])[0] == "";
}


