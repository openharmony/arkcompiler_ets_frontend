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

interface GeneratedTypeLiteralInterface_1 {
    x: number;
    y: number;
}
let o: GeneratedTypeLiteralInterface_1 = {
    x: 2,
    y: 3
}

interface GeneratedTypeLiteralInterface_2 {
    x: number;
    y: number;
}
type S = Set<GeneratedTypeLiteralInterface_2>

class C {
    x: number = 0
    y: number = 0
}

let c: C = {x: 2, y: 3}

type t = Set<C>