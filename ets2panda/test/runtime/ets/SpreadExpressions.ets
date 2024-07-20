/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

function compMultiArray<T>(arrayMulti1: T[][], arrayMulti2: T[][]) {
    let i : int = 0
    for (let element1 of arrayMulti1) {
        compArray<T>(element1, arrayMulti2[i])
        i++
    }
}

function compArray<T>(array1: T[], array2: T[]) {
    let i : int = 0
    for (let element1 of array1) {
        assert element1 == array2[i]
        i++
    }
}

function main() {
    let intArray : int[] = [77, 88, 99]

    // Array variable declaration with multi spread
    let expectedVarDecl : Int[] = [1, 2, 77, 88, 99, 4, 6, 77, 88, 99]
    let arrayVarDecl : Int[] = [1, 2, ...intArray, 4, 6, ...intArray]
    compArray<Int>(arrayVarDecl, expectedVarDecl)

    // Array assignment expression with multi spread
    let expectedAssignment : Int[] = [100, 200, 77, 88, 99, 400, 600, 77, 88, 99]
    let arrayAssignment : Int[]
    arrayAssignment = [100, 200, ...intArray, 400, 600, ...intArray]
    compArray<Int>(arrayAssignment, expectedAssignment)

    // Multi dimensional array
    let expectedArray : Int[][] = [[7, 8], [10, 77, 88, 99]]
    let arrayMulti : Int[][] = [[7, 8], [10, ...intArray]]
    compMultiArray<Int>(arrayMulti, expectedArray)

    // Union type array
    type unionType = (int|string|null)
    let unionArray : unionType[] = ["first", "second"]
    let expectedUnion : unionType[] = [100, 200, "first", "second", 500, 600, "first", "second"]
    let arrayUnion: unionType[] = [100, 200, ...unionArray, 500, 600, ...unionArray]
    compArray<unionType>(arrayUnion, expectedUnion)

    // Object array
    let obj : Object = new Object();
    let objectArray : Object[] = [obj, obj]
    let expectedObject : Object[] = [obj, obj, obj]
    let arrayObject : Object[] = [obj, ...objectArray]
    compArray<Object>(arrayObject, expectedObject)
}
