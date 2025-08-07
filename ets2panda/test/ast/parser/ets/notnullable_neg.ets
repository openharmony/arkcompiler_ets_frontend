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
    let foo = <T>(p: T): NonNullable<<<<<<<<<<<<<<<<<<<<<<<<<<<T> =>p;
}

/* @@? 17:15 Error SyntaxError: Type cast syntax '<type>' is not supported, please use 'as' keyword instead */
/* @@? 17:20 Error SyntaxError: Unexpected token, expected ')'. */
/* @@? 17:22 Error SyntaxError: Unexpected token 'T'. */
/* @@? 17:22 Error TypeError: Unresolved reference T */
/* @@? 17:23 Error SyntaxError: Unexpected token ')'. */
/* @@? 17:24 Error SyntaxError: Unexpected token ':'. */
/* @@? 17:26 Error SyntaxError: Unexpected token 'NonNullable'. */
/* @@? 17:26 Error TypeError: Unresolved reference NonNullable */
/* @@? 17:37 Error SyntaxError: Expected '>', got '<<'. */
/* @@? 17:37 Error SyntaxError: Expected '<', got '<<'. */
/* @@? 17:37 Error SyntaxError: Expected '>', got '<<'. */
/* @@? 17:37 Error SyntaxError: Expected '<', got '<<'. */
/* @@? 17:39 Error SyntaxError: Unexpected token '<<'. */
/* @@? 17:43 Error SyntaxError: Unexpected token '<<'. */
/* @@? 17:47 Error SyntaxError: Unexpected token '<<'. */
/* @@? 17:51 Error SyntaxError: Unexpected token '<<'. */
/* @@? 17:55 Error SyntaxError: Unexpected token '<<'. */
/* @@? 17:59 Error SyntaxError: Unexpected token '<<'. */
/* @@? 17:63 Error SyntaxError: Type cast syntax '<type>' is not supported, please use 'as' keyword instead */
/* @@? 17:67 Error SyntaxError: Unexpected token '=>'. */
/* @@? 17:69 Error SyntaxError: Unexpected token 'p'. */
/* @@? 17:69 Error TypeError: Unresolved reference p */
