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

let foo1 = <T>
let foo2 = <T>()
function main() {
    let foo3 = <T>
    let foo4 = <T>()
}

/* @@? 17:1 Error SyntaxError: Unexpected token, expected '('. */
/* @@? 18:1 Error SyntaxError: Unexpected token, expected '=>'. */
/* @@? 20:5 Error SyntaxError: Unexpected token, expected '('. */
/* @@? 21:1 Error SyntaxError: Unexpected token, expected '=>'. */
