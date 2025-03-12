/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

enum B {
    a = ()
}

enum C {
    a = )
}

enum D {
    a = 9?(1)
}


/* @@? 17:9 Error SyntaxError: Invalid enum initialization value */
/* @@? 17:10 Error SyntaxError: Unexpected token ')'. */
/* @@? 21:9 Error SyntaxError: Unexpected token ')'. */
/* @@? 21:9 Error SyntaxError: Unexpected token, expected ',' or '}'. */
/* @@? 21:9 Error SyntaxError: Unexpected token ')'. */
/* @@? 21:9 Error SyntaxError: Invalid enum initialization value */
/* @@? 22:1 Error SyntaxError: Unexpected token '}'. */
/* @@? 26:1 Error SyntaxError: Unexpected token, expected ':'. */
/* @@? 39:1 Error SyntaxError: Unexpected token 'eos'. */
/* @@? 39:1 Error SyntaxError: Unexpected token, expected ',' or '}'. */
