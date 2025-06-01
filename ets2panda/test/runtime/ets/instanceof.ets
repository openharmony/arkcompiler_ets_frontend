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

function bar() {}

function foo(): () => void {
    return bar;
}

function main(): void {
  let obj = new Boolean();
  let nobj: Object|null = null;

  assertTrue(null instanceof null)
  assertTrue(nobj instanceof null)
  assertTrue(!(obj instanceof null))

  let arr: int[] = [1, 2, 3];

  assertTrue(arr instanceof Object)
  assertTrue(!(arr instanceof Long))
  assertTrue(obj instanceof Object)
  assertTrue(obj instanceof Boolean)
  assertTrue(!(obj instanceof Long))

  let intArr: int[] = [1, 2, 3];

  assertTrue(intArr instanceof int[])
  assertTrue(intArr instanceof Object)
  assertTrue(!(intArr instanceof Long))
  assertTrue(!(intArr instanceof Int[]))
  assertTrue(!(intArr instanceof Int))

  let integerArr: Int[] = new Int[10];

  assertTrue(integerArr instanceof Int[])
  assertTrue(integerArr instanceof Object)
  assertTrue(!(intArr instanceof Double[]))
  assertTrue(!(integerArr instanceof int[]))
  assertTrue(!(integerArr instanceof Int))

  let integerArrArr: Int[][] = [[10], [20]];

  assertTrue(integerArrArr instanceof Int[][])
  assertTrue(integerArrArr instanceof Object)
  assertTrue(!(integerArrArr instanceof Int[]))
  assertTrue(!(integerArrArr instanceof Int))
  assertTrue(!(integerArrArr instanceof Long[][]))

  let f: () => void = foo();

  assertTrue(f instanceof (() => void))

  assertTrue(bar instanceof (() => void))

  return;
}

