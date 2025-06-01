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

    // Compile-time error with noImplicitAny
    function f(x: number) {
        if (x <= 0) {
            return x
        }
        return g(x)
    }

    // Compile-time error with noImplicitAny
    function g(x: number) {
        return f(x - 1)
    }

    function doOperation(x: number, y: number) {
        return x + y
    }

    console.log(f(10))
    console.log(doOperation(2, 3))

    function f1(x: number) : number {
        if (x <= 0) {
            return x
        }
        return g1(x)
    }

    function g1(x: number) {
        return f1(x - 1)
    }

    function doOperation1(x: number, y: number) {
        return x + y
    }

    console.log(f1(10))
    console.log(doOperation1(2, 3))
