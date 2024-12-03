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

-a ** 2;

< 2;

function f() {
    var a = 1--;
    var a = eval++;
    var a = arguments--;
    var a = ++1;
    var a = --arguments;
    var a = ++eval;

    delete a
    delete this.#a
}

import.meta
import.abc

(x ?? null || 1);
(x || null ?? 1);

let a = ({x, y...} = 7) => 0;
let a = (x, 10) => 0;
let a = (x, ...1) => 0;
let a = (...a, x);
let a = ();

a?.[1+2);
a?.`abc`;

let {async
    a, b} = {a: 1, b:2};

const obj = {
    get a(x) { return x + 1; },
    set a() { },
    b: 1
};

let {*a} = 0;
let {a(){}, b} = 0;
let {public } = 0;

[a, [a, b]] = [1, 2] ({...r, c} = {a: 10});

({a, ...r, b} = {a: 10, b: 20}) => expression;
({a, ...r, b} = 7) => expression;
([a, b = await 7]) => expression;
({...x, b}) => expression;
(...x = 4, [...x, b]) => expression;
(async f = await b()) => expression;
async (...x = await 4, a) => expression;
async (x = await 7) => expression;
(a, b) => { 7 ];
// This should be the last line to check syntax error about missing '}'

/* @@? 16:4 Error SyntaxError: Illegal expression. Wrap left hand side or entire exponentiation in parentheses.  */
/* @@? 18:1 Error SyntaxError: Unexpected token: '<'.  */
/* @@? 21:14 Error SyntaxError: Invalid left-hand side operator.  */
/* @@? 22:17 Error SyntaxError: Assigning to 'eval' in strict mode is invalid  */
/* @@? 23:22 Error SyntaxError: Assigning to 'arguments' in strict mode is invalid  */
/* @@? 24:16 Error SyntaxError: Invalid left-hand side in prefix operation  */
/* @@? 25:24 Error SyntaxError: Assigning to 'arguments' in strict mode is invalid  */
/* @@? 26:19 Error SyntaxError: Assigning to 'eval' in strict mode is invalid  */
/* @@? 29:5 Error SyntaxError: Deleting local variable in strict mode  */
/* @@? 30:1 Error SyntaxError: Private fields can not be deleted  */
/* @@? 32:1 Error SyntaxError: 'import' and 'export' may appear only with 'sourceType: module'  */
/* @@? 32:7 Error SyntaxError: 'import.Meta' may appear only with 'sourceType: module'  */
/* @@? 33:1 Error SyntaxError: 'import' and 'export' may appear only with 'sourceType: module'  */
/* @@? 33:7 Error SyntaxError: 'import.Meta' may appear only with 'sourceType: module'  */
/* @@? 33:8 Error SyntaxError: The only valid meta property for import is import.Meta  */
/* @@? 35:16 Error SyntaxError: Nullish coalescing operator ?? requires parens when mixing with logical operators.  */
/* @@? 36:16 Error SyntaxError: Nullish coalescing operator ?? requires parens when mixing with logical operators.  */
/* @@? 38:15 Error SyntaxError: Unexpected token, expected: ':'.  */
/* @@? 38:18 Error SyntaxError: Unexpected token: '}'.  */
/* @@? 39:17 Error SyntaxError: Insufficient formal parameter in arrow function.  */
/* @@? 40:16 Error SyntaxError: Unexpected token, expected an identifier.  */
/* @@? 40:16 Error SyntaxError: Unexpected token, expected: ')'.  */
/* @@? 40:17 Error SyntaxError: Unexpected token ')'.  */
/* @@? 40:17 Error SyntaxError: Unexpected token: ')'.  */
/* @@? 40:19 Error SyntaxError: Unexpected token: '=>'.  */
/* @@? 41:14 Error SyntaxError: Rest parameter must be the last formal parameter.  */
/* @@? 41:14 Error SyntaxError: Unexpected token, expected: '=>'.  */
/* @@? 41:17 Error SyntaxError: Unexpected token ')'.  */
/* @@? 41:17 Error SyntaxError: Unexpected token: ')'.  */
/* @@? 42:11 Error SyntaxError: Unexpected token, expected: '=>'.  */
/* @@? 44:8 Error SyntaxError: Unexpected token, expected: ']'.  */
/* @@? 45:4 Error SyntaxError: Tagged Template Literals are not allowed in optionalChain  */
/* @@? 48:5 Error SyntaxError: Async methods cannot have a line terminator between 'async' and the property name  */
/* @@? 48:6 Error SyntaxError: Unexpected identifier  */
/* @@? 48:6 Error SyntaxError: Unexpected token, expected: ':'.  */
/* @@? 47:5 Error SyntaxError: Invalid left-hand side in array destructuring pattern  */
/* @@? 51:31 Error SyntaxError: Getter must not have formal parameters  */
/* @@? 52:16 Error SyntaxError: Setter must have exactly one formal parameter  */
/* @@? 56:6 Error SyntaxError: Unexpected token  */
/* @@? 56:8 Error SyntaxError: Unexpected identifier  */
/* @@? 56:8 Error SyntaxError: Unexpected token, expected: ':'.  */
/* @@? 56:10 Error SyntaxError: Unexpected token, expected an identifier.  */
/* @@? 56:13 Error SyntaxError: Unexpected token, expected ',' or '}'  */
/* @@? 57:1 Error SyntaxError: Missing initializer in destructuring declaration  */
/* @@? 57:7 Error SyntaxError: Object pattern can't contain methods */
/* @@? 57:5 Error SyntaxError: Invalid left-hand side in array destructuring pattern */
/* @@? 58:6 Error SyntaxError: Unexpected token, expected an identifier. */
/* @@? 60:23 Error SyntaxError: Invalid left-hand side in array destructuring pattern */
/* @@? 62:33 Error SyntaxError: Invalid destructuring assignment target */
/* @@? 62:33 Error SyntaxError: Unexpected ArrowParameter element */
/* @@? 63:20 Error SyntaxError: Invalid destructuring assignment target */
/* @@? 63:20 Error SyntaxError: Unexpected ArrowParameter element */
/* @@? 64:16 Error SyntaxError: Unexpected token, expected ',' or ']' */
/* @@? 65:13 Error SyntaxError: Invalid destructuring assignment target */
/* @@? 65:13 Error SyntaxError: Unexpected ArrowParameter element */
/* @@? 66:7 Error SyntaxError: Unexpected token, expected: ')'. */
/* @@? 66:10 Error SyntaxError: Rest parameter must be the last formal parameter. */
/* @@? 66:10 Error SyntaxError: Unexpected token, expected: '=>'. */
/* @@? 66:21 Error SyntaxError: Unexpected token ')'. */
/* @@? 66:21 Error SyntaxError: Unexpected token: ')'. */
/* @@? 66:23 Error SyntaxError: Unexpected token: '=>'. */
/* @@? 67:10 Error SyntaxError: Unexpected token, expected: '=>'. */
/* @@? 67:23 Error SyntaxError: Unexpected token, arrow (=>) */
/* @@? 68:27 Error SyntaxError: Invalid rest element. */
/* @@? 68:27 Error SyntaxError: Unexpected ArrowParameter element */
/* @@? 69:21 Error SyntaxError: await is not allowed in arrow function parameters */
/* @@? 69:21 Error SyntaxError: Unexpected ArrowParameter element */
/* @@? 70:15 Error SyntaxError: Unexpected token ']'. */
/* @@? 70:15 Error SyntaxError: Unexpected token: ']'. */
/* @@? 143:1 Error SyntaxError: Unexpected token, expected: '}'. */
