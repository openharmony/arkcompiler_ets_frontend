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

/*---
flags: [dynamic-ast]
---*/

type Point = { x: number; y: number };
type AxeX = Point['x'];

/* @@? 20:14 Error SyntaxError: Invalid Type. */
/* @@? 20:19 Error SyntaxError: Label must be followed by a loop statement. */
/* @@? 20:19 Error TypeError: Type name 'number' used in the wrong context */
/* @@? 20:30 Error SyntaxError: Label must be followed by a loop statement. */
/* @@? 20:30 Error TypeError: Type name 'number' used in the wrong context */
/* @@? 21:19 Error SyntaxError: Unexpected token, expected ']'. */
/* @@? 21:19 Error SyntaxError: Invalid Type. */
/* @@? 21:19 Error SyntaxError: Unexpected token ']'. */
/* @@? 21:19 Error SyntaxError: Unexpected token ']'. */
/* @@? 21:22 Error SyntaxError: Unexpected token ']'. */
/* @@? 21:22 Error SyntaxError: Unexpected token ']'. */
