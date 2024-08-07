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

function foo(i: number) {
    this.count = i // Compile-time error only with noImplicitThis
}

class A {
    count: number = 1
    m = foo
}

let a = new A()
console.log(a.count) // prints "1"
a.m(2)
console.log(a.count) // prints "2"

class A1 {
    count: number = 1
    m(i: number): void {
        this.count = i
    }
}

function main(): void {
    let a = new A1()
    console.log(a.count)  // prints "1"
    a.m(2)
    console.log(a.count)  // prints "2"
}
