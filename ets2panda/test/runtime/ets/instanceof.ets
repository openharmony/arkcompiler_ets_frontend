/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

  assert (null instanceof null)
  assert (nobj instanceof null)
  assert (!(obj instanceof null))

  let arr: int[] = [1, 2, 3];

  assert (arr instanceof Object)
  assert (!(arr instanceof Long))
  assert (obj instanceof Object);
  assert (obj instanceof Boolean);
  assert (!(obj instanceof Long));

  let intArr: int[] = [1, 2, 3];

  assert (intArr instanceof int[]);
  assert (intArr instanceof Object);
  assert (!(intArr instanceof Long));
  assert (!(intArr instanceof Int[]));
  assert (!(intArr instanceof Int));

  let integerArr: Int[] = new Int[10];

  assert (integerArr instanceof Int[]);
  assert (integerArr instanceof Object);
  assert (!(intArr instanceof Double[]));
  assert (!(integerArr instanceof int[]));
  assert (!(integerArr instanceof Int));

  let integerArrArr: Int[][] = [[10], [20]];

  assert (integerArrArr instanceof Int[][]);
  assert (integerArrArr instanceof Object);
  assert (!(integerArrArr instanceof Int[]));
  assert (!(integerArrArr instanceof Int));
  assert (!(integerArrArr instanceof Long[][]));

  let f: () => void = foo();

  assert (f instanceof (() => void));

  return;
}

