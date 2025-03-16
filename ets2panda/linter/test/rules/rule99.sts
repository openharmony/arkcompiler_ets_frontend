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

function foo(x : number, y : number, z : number) {
    console.log(x, y, z)
}

let args : [number, number, number] = [0, 1, 2]
foo(...args)

let list1 = [1, 2]
let list2 = [...list1, 3, 4]

let point2d = {x: 1, y: 2}
let point3d = {...point2d, z: 3}




function sum_numbers(...numbers: number[]): number {
    let res = 0
    for (let n of numbers)
        res += n
    return res
}
console.log(sum_numbers(1, 2, 3))

function log_numbers(x : number, y : number, z : number) {
    console.log(x, y, z)
}
let numbers: number[] = [1, 2, 3]
log_numbers(numbers[0], numbers[1], numbers[2])

let list3 : number[] = [1, 2]
let list4 : number[] = [list1[0], list1[1], 3, 4]

class Point2D {
    x: number = 0; y: number = 0
}

class Point3D {
    x: number = 0; y: number = 0; z: number = 0
    constructor(p2d: Point2D, z: number) {
        this.x = p2d.x
        this.y = p2d.y
        this.z = z
    }
}

let p3d = new Point3D({x: 1, y: 2} as Point2D, 3)
console.log(p3d.x, p3d.y, p3d.z)

class DerivedFromArray extends Uint16Array {
};

let arr1 = [1, 2, 3];
let arr2 = new Uint16Array([4, 5, 6]);
let arr3 = new DerivedFromArray([7, 8, 9])

let arr4 = [...arr1, 10, ...arr2, 11, ...arr3]
