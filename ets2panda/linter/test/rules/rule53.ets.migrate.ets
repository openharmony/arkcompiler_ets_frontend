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

class Shape {}
class Circle extends Shape {x: number = 5}
class Square extends Shape {y: string = "a"}

function createShape(): Shape {
    return new Circle()
}

let c1 = createShape() as Circle

let c2 = createShape() as Circle

// No report is provided during compilation
// nor during runtime if cast is wrong:
let c3 = createShape() as Square
console.log(c3.y) // undefined

// Important corner case for casting primitives to the boxed counterparts:
// The left operand is not properly boxed here in in runtime
// because "as" has no runtime effect in TypeScript
let e1 = (5.0 as Number) instanceof Number // false

// Number object is created and instanceof works as expected:
let e2 = (new Number(5.0)) instanceof Number // true