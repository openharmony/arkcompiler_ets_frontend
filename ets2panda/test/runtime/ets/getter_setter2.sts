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

class A {
    _field: int = 30;

    get field(): int {
        return this._field;
    }

    set field(field: int): void {
        this._field = field;
    }
}

function main(): void {
    let objectos = new A;

    // left side
    objectos.field += 10;
    assert objectos.field == 40;

    objectos.field -= 200;
    assert objectos.field == -160;

    objectos.field += 260;
    objectos.field *= 10;
    assert objectos.field == 1000;

    objectos.field /= 100;
    assert objectos.field == 10;

    objectos.field = 16;
    objectos.field >>= 2
    assert objectos.field == 4;

    objectos.field = 16;
    objectos.field >>>= 1
    assert objectos.field == 8;

    objectos.field = 8;
    objectos.field <<= 1
    assert objectos.field == 16;

    objectos.field = 5;
    objectos.field %= 2
    assert objectos.field == 1;

    objectos.field = 15;
    objectos.field &= 7
    assert objectos.field == 7;

    objectos.field = 15;
    objectos.field |= 7
    assert objectos.field == 15;

    objectos.field = 15;
    objectos.field ^= 7
    assert objectos.field == 8;

    // left and right side

    objectos.field = 100;
    objectos.field += objectos.field;
    assert objectos.field == 200;

    objectos.field -= objectos.field;
    assert objectos.field == 0;

    objectos.field += 100;
    objectos.field *= objectos.field;
    assert objectos.field == 10000;

    objectos.field /= objectos.field;
    assert objectos.field == 1;

    objectos.field |= objectos.field
    assert objectos.field == 1;

    // right side

    let value = 100;
    objectos.field = 2;

    value += objectos.field;
    assert value == 102;

    value -= objectos.field;
    assert value == 100;

    value *= objectos.field;
    assert value == 200;

    value /= objectos.field;
    assert value == 100;

    value = 16;
    value >>= objectos.field
    assert value == 4;

    value = 16;
    value >>>= objectos.field
    assert value == 4;

    value = 8;
    value <<= objectos.field
    assert value == 32;

    value = 5;
    value %= objectos.field
    assert value == 1;

    value = 15;
    value &= objectos.field
    assert value == 2;

    value = 15;
    value |= objectos.field
    assert value == 15;

    value = 15;
    value ^= objectos.field
    assert value == 13;
}
