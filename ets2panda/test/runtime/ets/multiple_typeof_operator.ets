/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

class Y {}

function main() {
    let a : Int = 5

    assertEQ(typeof typeof 1, "string")
    assertEQ(typeof typeof typeof typeof typeof 5, "string")
    assertEQ(typeof typeof typeof typeof typeof typeof 1, "string")
    assertEQ(typeof typeof typeof typeof typeof typeof ++a, "string")
    assertEQ(typeof typeof typeof typeof typeof typeof a++, "string")

    let y = new Y();

    assertEQ(typeof y, "object")

    let typeof: int = 0;
    let x = typeof + 1
    ++typeof;

    assertEQ(typeof typeof, "number");
}
