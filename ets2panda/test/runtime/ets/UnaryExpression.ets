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
    let a: double = 10.0;
    let b = -a;
    assertEQ(b, -10.0)

    a = -a;
    assertEQ(a, -10.0)

    let c = +a;
    assertEQ(c, -10.0)
    assertEQ(+c, -10.0)
    assertEQ(-c, 10.0)
  }

  {
    let a: int = 20;
    let b = -a;
    assertEQ(b, -20)

    a = -a;
    assertEQ(a, -20)

    let c = +a;
    assertEQ(c, -20)
    assertEQ(+c, -20)
    assertEQ(-c, 20)
  }

  {
    let a: Double = new Double(30.0);
    let b = -a;
    assertEQ(b, -30.0)

    a = -a;
    assertEQ(a, -30.0)
    assertEQ(a.doubleValue(), -30.0)

    let c = +a;
    assertEQ(c, -30.0)
    assertEQ(+c, -30.0)
    assertEQ(-c, 30.0)
  }

  {
    let a: Int = new Int(40);
    let b = -a;
    assertEQ(b, -40)

    a = -a;
    assertEQ(a, -40)
    assertEQ(a.intValue(), -40)

    let c = +a;
    assertEQ(c, -40)
    assertEQ(+c, -40)
    assertEQ(-c, 40)
  }

  {
    let a = -new Int(50);
    assertEQ(a, -50)

    let b = -a;
    assertEQ(b, 50)

    let c = +a;
    assertEQ(c, -50)
    assertEQ(+c, -50)
    assertEQ(-c, 50)
  }

  {
    let a = +new Double(60.0);
    assertEQ(a, 60.0)

    let b = -a;
    assertEQ(b, -60.0)

    let c = +a;
    assertEQ(c, 60.0)
    assertEQ(+c, 60.0)
    assertEQ(-c, -60.0)
  }

  {
    let a = -(-1);
    assertEQ(a, 1);

    let b = -(1);
    assertEQ(b, -1);

    let c = - -1;
    assertEQ(c, 1);

    let d = +(1);
    assertEQ(d, 1);

    let e = +(-1);
    assertEQ(e, -1);

    let f = + -1;
    assertEQ(f, -1);
  }
}
