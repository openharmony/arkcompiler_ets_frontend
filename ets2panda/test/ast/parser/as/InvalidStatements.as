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

function f(): void {
    export * { name }
}

export {
    :
    number
    77
}

function s() {}

/* @@? 17:5 Error SyntaxError: 'import' and 'export' may only appear at the top level */
/* @@? 17:5 Error SyntaxError: 'import' and 'export' may appear only with 'sourceType: module' */
/* @@? 17:14 Error SyntaxError: Unexpected token '{', expected 'from'. */
/* @@? 17:14 Error SyntaxError: Unexpected token '{', expected 'string literal'. */
/* @@? 20:1 Error SyntaxError: 'import' and 'export' may appear only with 'sourceType: module' */
/* @@? 21:5 Error SyntaxError: Unexpected token ':'. */
/* @@? 22:5 Error SyntaxError: Unexpected token ':', expected an identifier. */
/* @@? 23:5 Error SyntaxError: Unexpected token 'number literal'. */
/* @@? 24:1 Error SyntaxError: Unexpected token 'number literal', expected an identifier. */
