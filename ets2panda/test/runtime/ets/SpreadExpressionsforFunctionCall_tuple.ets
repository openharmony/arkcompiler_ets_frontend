/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
    foo () : [int, string] {
        return [7, "a"]
    }
}

function foo() : [boolean, string, int]{
    return [true, "b", 1]
}

function getStringArr() : [int, boolean, string] {
    return [5, true, "A"]
}

function main() {
    let a = new A()
    let arr1 = [...a./*xxxxx*/foo(), ...foo()]
    assertEQ(arr1.length, 5)
    assertEQ(arr1[0], 7)
    assertEQ(arr1[1], "a")
    assertEQ(arr1[2], true)
    assertEQ(arr1[3], "b")
    assertEQ(arr1[4], 1)

    let arr2 = [...getStringArr()]
    assertEQ(arr2.length, 3)
    assertEQ(arr2[0], 5)
    assertEQ(arr2[1], true)
    assertEQ(arr2[2], "A")

    let getArr = (): [string, int] => {
        return ["a", 10]
    }
    let arr3 = [...arr2, ...getArr(), "B"]
    assertEQ(arr3.length, 6)
    assertEQ(arr3[0], 5)
    assertEQ(arr3[1], true)
    assertEQ(arr3[2], "A")
    assertEQ(arr3[3], "a")
    assertEQ(arr3[4], 10)
    assertEQ(arr3[5], "B")

}

