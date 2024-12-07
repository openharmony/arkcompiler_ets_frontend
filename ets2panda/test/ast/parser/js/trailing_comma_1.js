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

function foo(...number,) {
    return number[0]
}

function foo2(number,) {
    return number
}

function foo3(, number) {
    return number
}

let a = [1, , 2,,] // OK - omitted expressions
foo(...a,)
foo(a[0],)
foo(a[0], a[1], ...a,)
foo(a[0],,a[0])
foo(a[0],,)
foo(,a[0])
foo(a[0] a[1])
foo(,)


/* @@? 16:23 Error SyntaxError: Rest parameter must be the last formal parameter.  */
/* @@? 24:15 Error SyntaxError: Unexpected token, expected an identifier.  */
/* @@? 32:10 Error SyntaxError: Unexpected token: ','.  */
/* @@? 33:10 Error SyntaxError: Unexpected token: ','.  */
/* @@? 34:5 Error SyntaxError: Unexpected token: ','.  */
/* @@? 35:10 Error SyntaxError: Unexpected token, expected ',' or ')'.  */
/* @@? 35:10 Error SyntaxError: Unexpected token 'identification literal'.  */
/* @@? 35:14 Error SyntaxError: Unexpected token ')'.  */
/* @@? 35:14 Error SyntaxError: Unexpected token: ')'.  */
/* @@? 36:5 Error SyntaxError: Unexpected token: ','.  */
