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

async native function foo(): Promise;

/* @@? 16:7 Error SyntaxError: 'async' flags must be used for functions only at top-level. */
/* @@? 16:14 Error SyntaxError: Unexpected token, expected an identifier. */
/* @@? 16:14 Error SyntaxError: Unexpected token, expected '('. */
/* @@? 16:14 Error TypeError: Only abstract or native methods can't have body. */
/* @@? 16:26 Error SyntaxError: Parameter declaration should have an explicit type annotation. */
/* @@? 16:26 Error SyntaxError: Unexpected token, expected ',' or ')'. */
/* @@? 16:27 Error SyntaxError: Unexpected token ')'. */
/* @@? 16:28 Error SyntaxError: Unexpected token, expected ')'. */
/* @@? 16:30 Error SyntaxError: Unexpected token 'Promise'. */
/* @@? 16:30 Error TypeError: Class name 'Promise' used in the wrong context */
