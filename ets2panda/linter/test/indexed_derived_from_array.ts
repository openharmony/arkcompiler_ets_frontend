/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

let nextId: number = 0
class ObservedArray<T> extends Array<T> {}

let arr1 = new ObservedArray<number>(1, 2, 3)
console.log(arr1[0])
console.log(arr1[nextId])

class NumberArray extends Array<number> {}
let arr2 = new NumberArray(4, 5, 6)
console.log(arr2[0])
console.log(arr2[nextId])

class NumberTypedArray extends Uint32Array {}
let arr3 = new NumberTypedArray([7, 8, 9])
console.log(arr3[0])
console.log(arr3[nextId])

class A extends Uint32Array {}
class B extends A {}
class C extends B {}
let arr4 = new C([10, 11, 12])
console.log(arr4[0])
console.log(arr4[nextId])

class Point<T> extends Array<T> {
    constructor(x: T, y: T) {
        super(x, y)
    }
    
    public add(rhs: Point<T>): Point<T> {
        this[0] = this.compare(this[0], rhs[0], true);
        return this;
    }
    
    private compare(left: T, right: T, flag:boolean): T {
        return flag ? left : right
    }
}
    
class PointNumber extends Array<number> {
    constructor(x: number, y: number) {
        super(x, y)
    }
    
    public add(rhs: PointNumber): PointNumber {
        this[0] = this.compare(this[0], rhs[0], true);
        return this;
    }
    
    private compare(left: number, right: number, flag: boolean): number {
        return flag ? left : right
    }
}
