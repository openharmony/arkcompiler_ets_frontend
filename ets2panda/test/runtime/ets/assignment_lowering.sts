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

class B   {
    c: int = 11;
    d: int = 33;
    public constructor() {
        this.c += 22;
        this.d -= 44;
    }
}

function main(): void {

  let b = new B();
  assert (b.c == 33);
  assert (b.d == -11);

  let x: int[] = [1, 2, 3];

  for (let i: int = 0; i < 3; ++i) {
    i <<= 2;

    x[i >> 2] *= 2;
    i >>= 2;
  }

  for (let i: int = 0; i < 3; ++i) {
    assert (x[i] == (i + 1) * 2);
  }
}
