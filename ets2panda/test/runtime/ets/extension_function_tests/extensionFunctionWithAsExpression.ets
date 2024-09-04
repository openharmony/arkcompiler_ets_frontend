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

interface Fruit {}

function Fruit.foo(): int {
    return 1;
}

class Banana implements Fruit {}

function Banana.foo():int {
    return 2
}

function main() {
    let banana = new Banana();
    let res: int = banana.foo();
    assert res == 2 : "expected: " + 2 + " actual: " + res;
    let res1: int = (banana as Fruit).foo();
    assert res1 == 1 : "expected: " + 1 + " actual: " + res1;
}
