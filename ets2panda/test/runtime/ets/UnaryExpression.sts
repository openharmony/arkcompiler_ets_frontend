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
    let a: double = 10.0;
    let b = -a;
    assert b == -10.0;

    a = -a;
    assert a == -10.0;

    let c = +a;
    assert c == -10.0;
    assert +c == -10.0;
    assert -c == 10.0;
  }

  {
    let a: int = 20;
    let b = -a;
    assert b == -20;

    a = -a;
    assert a == -20;

    let c = +a;
    assert c == -20;
    assert +c == -20;
    assert -c == 20;
  }

  {
    let a: Double = new Double(30.0);
    let b = -a;
    assert b == -30.0;

    a = -a;
    assert a == -30.0;
    assert a.doubleValue() == -30.0;

    let c = +a;
    assert c == -30.0;
    assert +c == -30.0;
    assert -c == 30.0;
  }

  {
    let a: Int = new Int(40);
    let b = -a;
    assert b == -40;

    a = -a;
    assert a == -40;
    assert a.intValue() == -40;

    let c = +a;
    assert c == -40;
    assert +c == -40;
    assert -c == 40;
  }

  {
    let a = -new Int(50);
    assert a == -50;

    let b = -a;
    assert b == 50;

    let c = +a;
    assert c == -50;
    assert +c == -50;
    assert -c == 50;
  }

  {
    let a = +new Double(60.0);
    assert a == 60.0;

    let b = -a;
    assert b == -60.0;

    let c = +a;
    assert c == 60.0;
    assert +c == 60.0;
    assert -c == -60.0;
  }
}
