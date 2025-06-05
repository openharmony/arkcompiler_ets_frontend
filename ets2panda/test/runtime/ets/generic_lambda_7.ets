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

class A {}

function foo(f: <T>(t: T) => T) {
    let i1: number = 1.0
    assertEQ(f(i1), i1)
    assertEQ(f<number>(i1), i1)
    let i2: string = "abc"
    assertEQ(f(i2), i2)
    assertEQ(f<string>(i2), i2)
    let i3: A = new A()
    assertEQ(f(i3), i3)
    assertEQ(f<A>(i3), i3)
}

function main() {
    foo(<T>(t: T): T => t)
}
