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


function main(): void {
    let a: [number, string, ...Int[]] = [2, "a", 3];
    let b: [number, string, Int] = /* @@ label */a;
}

/* @@? 18:29 Error SyntaxError: Invalid Type. */
/* @@? 18:29 Error SyntaxError: Unexpected token, expected ',' or ']'. */
/* @@? 18:29 Error SyntaxError: Unexpected token '...'. */
/* @@? 18:32 Error SyntaxError: Unexpected token 'Int'. */
/* @@? 18:37 Error SyntaxError: Unexpected token ']'. */
