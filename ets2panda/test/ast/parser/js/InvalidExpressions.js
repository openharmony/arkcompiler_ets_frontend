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

-a /* @@ label */** 2;

/* @@ label1 */< 2;

function f() {
    var a = 1/* @@ label2 */--;
    var a = eval/* @@ label3 */++;
    var a = arguments/* @@ label4 */--;
    var a = ++1/* @@ label5 */;
    var a = --arguments/* @@ label6 */;
    var a = ++eval/* @@ label7 */;

    delete a
    /* @@ label8 */delete this.#a
/* @@ label9 */}

/* @@ label10 */import/* @@ label11 */.meta
/* @@ label12 */import/* @@ label13 */./* @@ label14 */abc

(x ?? null || 1/* @@ label15 */);
(x || null ?? 1/* @@ label16 */);

let a = ({x, y/* @@ label17 */.../* @@ label18 */} = 7) => 0;
let a = (x, 10) /* @@ label19 */=> 0;
let a = (x, .../* @@ label20 */1/* @@ label21 */) /* @@ label22 */=> 0;
let a = (...a/* @@ label23 */, x/* @@ label24 */);
let a = ()/* @@ label25 */;

a?.[1+2/* @@ label26 */);
a?./* @@ label27 */`abc`;

let /* @@ label28 */{async
    /* @@ label29 */a/* @@ label30 */, b} = {a: 1, b:2};

const obj = {
    get a(x) { return x + 1; }/* @@ label31 */,
    set a() { }/* @@ label32 */,
    b: 1
};

let {/* @@ label33 */*a/* @@ label34 */} /* @@ label35 */= 0/* @@ label36 */;
/* @@ label37 */let /* @@ label38 */{a/* @@ label39 */(){}, b} = 0;
let {/* @@ label40 */public } = 0;

[a, [a, b]] = [1, 2] (/* @@ label41 */{...r, c} = {a: 10});

({a, ...r, b} = {a: 10, b: 20}) /* @@ label42 */=> expression;
({a, ...r, b} = 7) /* @@ label43 */=> expression;
([a, b = await /* @@ label44 */7/* @@ label45 */]/* @@ label46 */) /* @@ label47 */=> expression;
({...x, b}) /* @@ label48 */=> expression;
(...x /* @@ label49 */= 4/* @@ label50 */, [...x, b]/* @@ label51 */) /* @@ label52 */=> expression;
(async f /* @@ label53 */= await b()) /* @@ label54 */=> expression;
async (...x = await 4, a) /* @@ label55 */=> expression;
async (x = await 7) /* @@ label56 */=> expression;
(a, b) => { 7 /* @@ label57 */];
// This should be the last line to check syntax error about missing '}'

/* @@@ label Error SyntaxError: Illegal expression. Wrap left hand side or entire exponentiation in parentheses.  */
/* @@@ label1 Error SyntaxError: Unexpected token '<'.  */
/* @@@ label2 Error SyntaxError: Invalid left-hand side operator.  */
/* @@@ label3 Error SyntaxError: Assigning to 'eval' in strict mode is invalid.  */
/* @@@ label4 Error SyntaxError: Assigning to 'arguments' in strict mode is invalid.  */
/* @@@ label5 Error SyntaxError: Invalid left-hand side in prefix operation.  */
/* @@@ label6 Error SyntaxError: Assigning to 'arguments' in strict mode is invalid.  */
/* @@@ label7 Error SyntaxError: Assigning to 'eval' in strict mode is invalid.  */
/* @@@ label8 Error SyntaxError: Deleting local variable in strict mode.  */
/* @@@ label9 Error SyntaxError: Private fields can not be deleted.  */
/* @@@ label10 Error SyntaxError: 'import.Meta' may appear only with 'sourceType: module'.  */
/* @@@ label11 Error SyntaxError: 'import.Meta' may appear only with 'sourceType: module'.  */
/* @@@ label12 Error SyntaxError: 'import.Meta' may appear only with 'sourceType: module'.  */
/* @@@ label13 Error SyntaxError: 'import.Meta' may appear only with 'sourceType: module'.  */
/* @@@ label14 Error SyntaxError: The only valid meta property for import is import.Meta.  */
/* @@@ label15 Error SyntaxError: Nullish coalescing operator ?? requires parens when mixing with logical operators.  */
/* @@@ label16 Error SyntaxError: Nullish coalescing operator ?? requires parens when mixing with logical operators.  */
/* @@@ label17 Error SyntaxError: Unexpected token, expected ':'.  */
/* @@@ label18 Error SyntaxError: Unexpected token '}'.  */
/* @@@ label19 Error SyntaxError: Insufficient formal parameter in arrow function.  */
/* @@@ label20 Error SyntaxError: Unexpected token '1'.  */
/* @@@ label20 Error SyntaxError: Unexpected token.  */
/* @@@ label20 Error SyntaxError: Expected ')', got 'number literal'.  */
/* @@@ label21 Error SyntaxError: Unexpected token ')'.  */
/* @@@ label21 Error SyntaxError: Unexpected token ')'.  */
/* @@@ label21 Error SyntaxError: Unexpected token ')'.  */
/* @@@ label22 Error SyntaxError: Unexpected token '=>'.  */
/* @@@ label23 Error SyntaxError: Rest parameter must be the last formal parameter.  */
/* @@@ label23 Error SyntaxError: Unexpected token, expected '=>'.  */
/* @@@ label24 Error SyntaxError: Unexpected token ')'.  */
/* @@@ label24 Error SyntaxError: Unexpected token ')'.  */
/* @@@ label24 Error SyntaxError: Unexpected token ')'.  */
/* @@@ label25 Error SyntaxError: Unexpected token, expected '=>'.  */
/* @@@ label26 Error SyntaxError: Unexpected token, expected ']'.  */
/* @@@ label27 Error SyntaxError: Tagged Template Literals are not allowed in optionalChain.  */
/* @@@ label28 Error SyntaxError: Invalid left-hand side in array destructuring pattern.  */
/* @@@ label29 Error SyntaxError: Async methods cannot have a line terminator between 'async' and the property name.  */
/* @@@ label30 Error SyntaxError: Unexpected identifier.  */
/* @@@ label30 Error SyntaxError: Unexpected token, expected ':'.  */
/* @@@ label31 Error SyntaxError: Getter must not have formal parameters.  */
/* @@@ label32 Error SyntaxError: Setter must have exactly one formal parameter.  */
/* @@@ label33 Error SyntaxError: Unexpected token.  */
/* @@@ label34 Error SyntaxError: Unexpected token, expected ':'.  */
/* @@@ label34 Error SyntaxError: Unexpected identifier.  */
/* @@@ label35 Error SyntaxError: Unexpected token.  */
/* @@@ label36 Error SyntaxError: Unexpected token.  */
/* @@@ label37 Error SyntaxError: Missing initializer in destructuring declaration.  */
/* @@@ label38 Error SyntaxError: Invalid left-hand side in array destructuring pattern.  */
/* @@@ label39 Error SyntaxError: Object pattern can't contain methods.  */
/* @@@ label40 Error SyntaxError: Unexpected token, expected an identifier.  */
/* @@@ label41 Error SyntaxError: Invalid left-hand side in array destructuring pattern.  */
/* @@@ label42 Error SyntaxError: Invalid destructuring assignment target.  */
/* @@@ label42 Error SyntaxError: Unexpected ArrowParameter element.  */
/* @@@ label43 Error SyntaxError: Invalid destructuring assignment target.  */
/* @@@ label43 Error SyntaxError: Unexpected ArrowParameter element.  */
/* @@@ label44 Error SyntaxError: Unexpected token, expected ',' or ']'.  */
/* @@@ label44 Error SyntaxError: Expected ')', got 'number literal'.  */
/* @@@ label44 Error SyntaxError: Unexpected token '7'.  */
/* @@@ label45 Error SyntaxError: Unexpected token ']'.  */
/* @@@ label45 Error SyntaxError: Unexpected token ']'.  */
/* @@@ label45 Error SyntaxError: Unexpected token ']'.  */
/* @@@ label46 Error SyntaxError: Unexpected token ')'.  */
/* @@@ label46 Error SyntaxError: Unexpected token ')'.  */
/* @@@ label47 Error SyntaxError: Unexpected token '=>'.  */
/* @@@ label48 Error SyntaxError: Invalid destructuring assignment target.  */
/* @@@ label48 Error SyntaxError: Unexpected ArrowParameter element.  */
/* @@@ label49 Error SyntaxError: Unexpected token, expected ')'.  */
/* @@@ label50 Error SyntaxError: Rest parameter must be the last formal parameter.  */
/* @@@ label50 Error SyntaxError: Unexpected token, expected '=>'.  */
/* @@@ label51 Error SyntaxError: Unexpected token ')'.  */
/* @@@ label51 Error SyntaxError: Unexpected token ')'.  */
/* @@@ label51 Error SyntaxError: Unexpected token ')'.  */
/* @@@ label52 Error SyntaxError: Unexpected token '=>'.  */
/* @@@ label53 Error SyntaxError: Unexpected token, expected '=>'.  */
/* @@@ label54 Error SyntaxError: Unexpected token.  */
/* @@@ label55 Error SyntaxError: Invalid rest element.  */
/* @@@ label55 Error SyntaxError: Unexpected ArrowParameter element.  */
/* @@@ label56 Error SyntaxError: await is not allowed in arrow function parameters.  */
/* @@@ label56 Error SyntaxError: Unexpected ArrowParameter element.  */
/* @@@ label57 Error SyntaxError: Unexpected token ']'.  */
/* @@@ label57 Error SyntaxError: Unexpected token ']'.  */
/* @@@ label57 Error SyntaxError: Unexpected token ']'.  */
/* @@? 156:1 Error SyntaxError: Expected '}', got 'end of stream'.  */
