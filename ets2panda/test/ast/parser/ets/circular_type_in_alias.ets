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

type Loop<T, U extends Loop<T, U>> = {
    [P in keyof T]: U[P] extends boolean ? number : string;
};

/* @@? 16:24 Error TypeError: Circular type alias reference */
/* @@? 16:38 Error SyntaxError: Invalid Type. */
/* @@? 17:6 Error TypeError: Unresolved reference P */
/* @@? 17:8 Error SyntaxError: Unexpected token, expected ',' or ']'. */
/* @@? 17:8 Error SyntaxError: Unexpected token 'in'. */
/* @@? 17:8 Error TypeError: Unresolved reference in */
/* @@? 17:11 Error SyntaxError: Unexpected token 'keyof'. */
/* @@? 17:11 Error TypeError: Unresolved reference keyof */
/* @@? 17:17 Error SyntaxError: Unexpected token 'T'. */
/* @@? 17:17 Error TypeError: Unresolved reference T */
/* @@? 17:18 Error SyntaxError: Unexpected token ']'. */
/* @@? 17:18 Error SyntaxError: Unexpected token ']'. */
/* @@? 17:18 Error SyntaxError: Unexpected token ']'. */
/* @@? 17:19 Error SyntaxError: Unexpected token ':'. */
/* @@? 17:19 Error SyntaxError: Unexpected token ':'. */
/* @@? 17:21 Error TypeError: Unresolved reference U */
/* @@? 17:21 Error TypeError: Indexed access is not supported for such expression type. */
/* @@? 17:26 Error SyntaxError: Unexpected token 'extends'. */
/* @@? 17:26 Error SyntaxError: Unexpected token 'extends'. */
/* @@? 17:26 Error SyntaxError: Unexpected token 'extends'. */
/* @@? 17:34 Error SyntaxError: Unexpected token 'boolean'. */
/* @@? 17:34 Error SyntaxError: Unexpected token 'boolean'. */
/* @@? 17:42 Error SyntaxError: Unexpected token '?'. */
/* @@? 17:44 Error TypeError: Type name 'number' used in the wrong context */
/* @@? 17:53 Error TypeError: Type name 'string' used in the wrong context */
