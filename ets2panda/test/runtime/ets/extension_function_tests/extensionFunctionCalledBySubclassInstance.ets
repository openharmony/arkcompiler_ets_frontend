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

class Fruit {
}

class Banana extends Fruit {

}

function name(this: Fruit): int {
    return 1;
}

function asFuncCall() {
    let banana = new Banana();
    let res: int = name(banana);
    assertEQ(res, 1 )
}

function asMethodCall() {
    let banana = new Banana();
    let res: int = banana.name();
    assertEQ(res, 1 )
}

function main() {
    asFuncCall();
    asMethodCall();
}
