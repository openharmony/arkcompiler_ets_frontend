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

const constchar: char = c'p'

function main() {
    const constcharToByte = constchar as byte
    assertEQ(constcharToByte ,112)
    enum TestEnum1 { One = constcharToByte }
    assertEQ(TestEnum1.One.valueOf(),112)

    const constcharToShort = constchar as short
    assertEQ(constcharToShort ,112)
    enum TestEnum2 { One = constcharToShort }
    assertEQ(TestEnum2.One.valueOf(),112)

    const constcharToInt = constchar as int
    assertEQ(constcharToInt ,112)
    enum TestEnum3 { One = constcharToInt }
    assertEQ(TestEnum3.One.valueOf(),112)

    const constcharToLong = constchar as long
    assertEQ(constcharToLong ,112)
    enum TestEnum4 { One = constcharToLong }
    assertEQ(TestEnum4.One.valueOf(),112)
}
