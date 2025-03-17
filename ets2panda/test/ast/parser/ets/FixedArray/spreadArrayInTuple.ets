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

function main() {
    let x1 = [1, "a"]
    let y1: [int, string] = /* @@ label */[/* @@ label1 */...x1]
    let x2 = [2, "b"]
    let y2: [boolean, int, string] = /* @@ label2 */[true, /* @@ label3 */...x2]
}

/* @@? 18:43 Error TypeError: Initializer has 1 elements, but tuple requires 2 */
/* @@? 18:59 Error TypeError: '(Int|String)[]' cannot be spread in tuple. */
/* @@? 20:53 Error TypeError: Initializer has 2 elements, but tuple requires 3 */
/* @@? 20:75 Error TypeError: '(Int|String)[]' cannot be spread in tuple. */
