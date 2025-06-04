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

type A = int;
type B = short;
let x: G<A, B> // OK
let y: G<{a:String}, B> // Error

/* @@? 18:8 Error TypeError: Cannot find type 'G'. */
/* @@? 19:8 Error TypeError: Cannot find type 'G'. */
/* @@? 19:10 Error SyntaxError: Unexpected token, expected '>'. */
/* @@? 19:10 Error SyntaxError: Unexpected token '>'. */
/* @@? 19:10 Error SyntaxError: Unexpected token '>'. */
/* @@? 19:10 Error SyntaxError: Invalid Type. */
/* @@? 19:11 Error TypeError: Unresolved reference a */
/* @@? 19:12 Error SyntaxError: Unexpected token ':'. */
/* @@? 19:13 Error TypeError: Class name 'String' used in the wrong context */
/* @@? 19:19 Error SyntaxError: Unexpected token '}'. */
/* @@? 19:20 Error SyntaxError: Unexpected token ','. */
/* @@? 19:20 Error SyntaxError: Unexpected token ','. */
/* @@? 19:22 Error TypeError: Type name 'B' used in the wrong context */
/* @@? 19:22 Error TypeError: Bad operand type, the types of the operands must be numeric, same enumeration, or boolean type. */
/* @@? 36:1 Error SyntaxError: Unexpected token 'eos'. */
