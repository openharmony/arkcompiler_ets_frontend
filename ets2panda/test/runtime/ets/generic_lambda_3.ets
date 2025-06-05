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
    let foo = <T> (p: T) : T => {
        let t: T = p
        return t
    }

    // Explicitly deducing generics
    let res1 = foo<int>(1)
    assertEQ(res1, 1)

    let res2 = foo<double>(1.5)
    assertEQ(res2, 1.5)

    let res3 = foo<string>("abc")
    assertEQ(res3, "abc")

    // Implicit derivation of generics
    let res4 = foo(1)
    assertEQ(res4, 1)

    let res5 = foo(1.5)
    assertEQ(res5, 1.5)

    let res6 = foo("abc")
    assertEQ(res6, "abc")
}
