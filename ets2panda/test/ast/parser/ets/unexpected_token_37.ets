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

/* @@ label */try
/* @@ label1 */catch (e/* @@ label2 */: Error/* @@ label3 */) {

} finally /* @@ label4 */{
    console.log("h")
}

/* @@@ label Error SyntaxError: A try statement should contain either finally clause or at least one catch clause. */
/* @@@ label1 Error SyntaxError: Expected '{', got 'identification literal'. */
/* @@@ label2 Error SyntaxError: Unexpected token, expected ',' or ')'. */
/* @@@ label2 Error SyntaxError: Unexpected token ':'. */
/* @@? 17:41 Error SyntaxError: Unexpected token 'Error'. */
/* @@@ label3 Error SyntaxError: Unexpected token ')'. */
/* @@? 17:63 Error SyntaxError: Unexpected token '{'. */
/* @@@ label4 Error SyntaxError: Unexpected token '{'. */
/* @@? 32:1 Error SyntaxError: Expected '}', got 'end of stream'. */
