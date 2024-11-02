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

let a = (x: int): void
=> {};

let a = (x
         => 10);

let a = (x: int, y:int): void) => {};

a # 19;
a#name;

let x = new.target(17);
let x = new import("file.ts");
let x = new Type(a, ...);
let x = new Type(1, 2, ;
// This expression should be the last to test EOS.

/* @@? 17:1 Error SyntaxError: expected '=>' on the same line after an argument list, got line terminator */
/* @@? 20:10 Error SyntaxError: Uncaught SyntaxError: expected expression, got '=>' */
/* @@? 20:10 Error SyntaxError: expected '=>' on the same line after an argument list, got line terminator */
/* @@? 22:13 Error SyntaxError: Unexpected token. */
/* @@? 22:20 Error SyntaxError: Unexpected token. */
/* @@? 22:24 Error SyntaxError: Unexpected token ':'. */
/* @@? 22:24 Error SyntaxError: Unexpected token: ':'. */
/* @@? 22:30 Error SyntaxError: Unexpected token: ')'. */
/* @@? 22:30 Error SyntaxError: Unexpected token: ')'. */
/* @@? 22:32 Error SyntaxError: Unexpected token: '=>'. */
/* @@? 24:3 Error SyntaxError: Unexpected token '#'. */
/* @@? 24:5 Error SyntaxError: Unexpected token in private field */
/* @@? 25:2 Error SyntaxError: Unexpected token '#'. */
/* @@? 25:7 Error SyntaxError: Unexpected private identifier */
/* @@? 27:1 Error SyntaxError: Unexpected token: 'let'. */
/* @@? 27:13 Error SyntaxError: 'new.Target' is not allowed here */
/* @@? 28:30 Error SyntaxError: Cannot use new with import(...) */
/* @@? 29:24 Error SyntaxError: Unexpected token: ')'. */
/* @@? 30:24 Error SyntaxError: Unexpected token: ';'. */
/* @@? 54:1 Error SyntaxError: Unexpected token: 'eos'. */
/* @@? 54:1 Error SyntaxError: Unexpected token in argument parsing */
