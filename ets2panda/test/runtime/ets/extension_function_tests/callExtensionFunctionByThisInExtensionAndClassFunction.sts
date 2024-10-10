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

class Fruit {
    name(): int {
        return 2 + this.amount();
    }

    public price: int = 5;
}

function Fruit.name(id: int): int {
    return id + this.name() + this.price;
}

function Fruit.price(): int {
    return this.name() + this.price + this.name(2);
}

function Fruit.amount(): int {
    return 6;
}

function main() {
    let fruit = new Fruit();
    let res = fruit.price();
    assert res == 28 : "expected: " + 28 + " actual: " + res;
}
