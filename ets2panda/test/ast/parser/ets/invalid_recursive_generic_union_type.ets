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

// Recursive generic union type test case migrated for ArkTS 1.2

// ArkTS does not support recursive type aliases or type declarations inside namespaces.
// We flatten the structure and define types globally to avoid unsupported features.

type Container<T> = T | { [i: string]: Container<T> };

declare namespace Test1 {
}

/* @@? 21:25 Error SyntaxError: Invalid Type. */
/* @@? 21:28 Error TypeError: Unresolved reference i */
/* @@? 21:29 Error SyntaxError: Unexpected token, expected ',' or ']'. */
/* @@? 21:29 Error SyntaxError: Unexpected token ':'. */
/* @@? 21:31 Error SyntaxError: Unexpected token 'string'. */
/* @@? 21:31 Error TypeError: Type name 'string' used in the wrong context */
/* @@? 21:37 Error SyntaxError: Unexpected token ']'. */
/* @@? 21:38 Error SyntaxError: Unexpected token ':'. */
/* @@? 21:40 Error SyntaxError: Unexpected token 'Container'. */
/* @@? 21:40 Error TypeError: This expression is not callable. */
/* @@? 21:50 Error TypeError: Cannot find type 'T'. */
/* @@? 21:53 Error SyntaxError: Unexpected token, expected '('. */
/* @@? 21:54 Error SyntaxError: Unexpected token ';'. */
/* @@? 23:1 Error SyntaxError: Unexpected token, expected ',' or ')'. */
/* @@? 23:1 Error TypeError: Unresolved reference declare */
/* @@? 23:9 Error SyntaxError: Namespace is allowed only at the top level or inside a namespace. */
/* @@? 23:9 Error SyntaxError: Unexpected token 'namespace'. */
/* @@? 44:1 Error SyntaxError: Expected '}', got 'end of stream'. */
