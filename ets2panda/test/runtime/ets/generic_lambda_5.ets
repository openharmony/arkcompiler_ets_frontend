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

function main() {
    let foo1 = <T>(t: int) => {
        return 1;
    }
    arktest.assertEQ(foo1(1), 1)

    let foo2 = <T>(t: int) => {
        return t;
    }
    arktest.assertEQ(foo2(1), 1)
    arktest.assertEQ(foo2(100), 100)

    let foo3 = <T>(t: T) => {
        return t;
    }
    arktest.assertEQ(foo3(1), 1)
    arktest.assertEQ(foo3("123"), "123")

    let foo4 = <T, U>(t: T, u: U) => {
        return t;
    }
    arktest.assertEQ(foo4(1, 1), 1)
    arktest.assertEQ(foo4(100, 1), 100)
    arktest.assertEQ(foo4(100, "abc"), 100)
    arktest.assertEQ(foo4("abc", 100), "abc")
}
