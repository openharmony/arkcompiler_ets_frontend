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

import { X, Y, foo, bar } from "./oh_modules/static_object_literals_export"

let x: X = { name: "hello" }

let a: X = new X("hello") // legal

let y: Y = { data: 123 }

let b: Y = createY(123) // legal

foo({ name: "world" });

foo(new X("world")) // legal

bar({ data: 456 });

bar(createY(456)) // legal

function zoo(): X {
    return { name: "hello" }
}

interface Z { x: X }

let z: Z = { x: { name: "hello" } }




