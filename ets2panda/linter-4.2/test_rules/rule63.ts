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

enum E { E1, E2 }

let a = 10 + 32   // 42
let b = E.E1 + 10 // 10
let c = 10 + "5"  // "105"

let d = "5" + E.E2 // "51"
let e = "Hello, " + "world!" // "Hello, world!"
let f = "string" + true // "stringtrue"

let g = (new Object()) + "string" // "[object Object]string"

let i = true + true // JS: 2, TS: compile-time error
let j = true + 2 // JS: 3, TS: compile-time error
let k = E.E1 + true // JS: 1, TS: compile-time error