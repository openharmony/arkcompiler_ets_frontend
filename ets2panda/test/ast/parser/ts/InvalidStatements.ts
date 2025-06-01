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

try {
    let x = 8
}

try {}
finally (x)

try {}
catch () {}

declare namespace abc {
    let i = 0
}

function f(): void {
    abstract function s(): void {}
}

function f(): void {
    module "module1" let x = 99;
}

interface A {
    a: number;
    a: char;
}

class A {
    declare [index: string]]: string;

    @decorator
    [index: string]]: MyType;

    @decorator
    private x: number;

    @decorator
    constructor() {}

    x! number;
}

class A {
    [index: number]]?: string;

    constructor?(x: number) {}
}

class A implements A. {}

const x: number;

let [x, y];

enum A
    I1,
    I2,
    123,
    123 = 55,
    I3 = ,
    I4
}

class A<123> {}

class A<T = Number, S> {}

class A<> {}

class B {
    abstract class C;

    private public x: number;
    protected protected x: number;

    constructor(static x: number) {}
}

let f = (a?: number, a: string) => {};
let f = (arguments: bool[], eval: bool) => {};
let f = ([a!, [b]?, c?]) => {};
let f = (a?: [c: int, d?: char]) => {};
let f = ({a: 123, b: bool}) => {};
let f = (a: int = await 10, a?: int = 2) => {};

declare namespace abc {
    let a = 8;
}

module {
    declare function s(): void;
}

module module2
    declare namespace abc {}
// This should be the last test to show the absent of the '}'.

/* @@? 20:1 Error SyntaxError: Missing catch or finally clause. */
/* @@? 21:9 Error SyntaxError: Expected '{', got '('. */
/* @@? 24:8 Error SyntaxError: Unexpected token ')'. */
/* @@? 27:13 Error SyntaxError: Initializers are not allowed in ambient contexts. */
/* @@? 31:14 Error SyntaxError: Abstract methods can only appear within an abstract class. */
/* @@? 35:12 Error SyntaxError: Only ambient modules can use quoted names. */
/* @@? 35:22 Error SyntaxError: Unexpected token, expected ';'. */
/* @@? 40:5 Error SyntaxError: Duplicated identifier. */
/* @@? 44:37 Error SyntaxError: A 'declare' modifier cannot be used in an already ambient context. */
/* @@? 46:5 Error SyntaxError: Decorators are not valid here. */
/* @@? 52:5 Error SyntaxError: Decorators are not valid here. */
/* @@? 55:6 Error SyntaxError: Unexpected token, expected ';'. */
/* @@? 55:8 Error SyntaxError: Unexpected token, expected ';'. */
/* @@? 59:21 Error SyntaxError: Unexpected token, expected ';'. */
/* @@? 61:5 Error SyntaxError: Classes may not have a field named 'constructor'. */
/* @@? 61:16 Error SyntaxError: Unexpected token, expected '('. */
/* @@? 64:23 Error SyntaxError: Identifier expected. */
/* @@? 68:11 Error SyntaxError: Missing initializer in destructuring declaration. */
/* @@? 71:5 Error SyntaxError: Expected '{', got 'identification literal'. */
/* @@? 71:7 Error SyntaxError: Unexpected token in enum member. */
/* @@? 72:5 Error SyntaxError: Unexpected token, expected ',' or '}'. */
/* @@? 74:9 Error SyntaxError: Invalid left-hand side in assignment expression. */
/* @@? 75:10 Error SyntaxError: Unexpected token ','. */
/* @@? 79:9 Error SyntaxError: Type parameter declaration expected. */
/* @@? 79:9 Error SyntaxError: Unexpected token, expected '>'. */
/* @@? 79:12 Error SyntaxError: Expected '{', got '>'. */
/* @@? 79:14 Error SyntaxError: Unexpected token. */
/* @@? 81:22 Error SyntaxError: Required type parameters may not follow optional type parameters. */
/* @@? 83:9 Error SyntaxError: Type parameter list cannot be empty. */
/* @@? 86:14 Error SyntaxError: Abstract methods can only appear within an abstract class. */
/* @@? 86:20 Error SyntaxError: Unexpected token, expected ';'. */
/* @@? 88:13 Error SyntaxError: Unexpected modifier. */
/* @@? 89:15 Error SyntaxError: Unexpected modifier. */
/* @@? 89:15 Error SyntaxError: Duplicated modifier is not allowed. */
/* @@? 91:17 Error SyntaxError: 'static' modifier cannot appear on a parameter. */
/* @@? 94:22 Error SyntaxError: A required parameter cannot follow an optional parameter. */
/* @@? 95:10 Error SyntaxError: 'eval' or 'arguments' can't be defined or assigned to in strict mode code. */
/* @@? 95:29 Error SyntaxError: 'eval' or 'arguments' can't be defined or assigned to in strict mode code. */
/* @@? 95:41 Error SyntaxError: Binding 'eval' in strict mode is invalid. */
/* @@? 95:41 Error SyntaxError: Binding 'arguments' in strict mode is invalid. */
/* @@? 96:18 Error SyntaxError: Unexpected '?' for parameter. */
/* @@? 96:26 Error SyntaxError: Invalid destructuring assignment target. */
/* @@? 96:26 Error SyntaxError: Unexpected ArrowParameter element. */
/* @@? 96:26 Error SyntaxError: Unexpected ArrowParameter element. */
/* @@? 98:29 Error SyntaxError: Invalid destructuring assignment target. */
/* @@? 99:29 Error SyntaxError: Parameter cannot have question mark and initializer. */
/* @@? 99:42 Error SyntaxError: await is not allowed in arrow function parameters. */
/* @@? 102:13 Error SyntaxError: Initializers are not allowed in ambient contexts. */
/* @@? 105:8 Error SyntaxError: Unexpected token, expected an identifier. */
/* @@? 106:5 Error SyntaxError: Unexpected token, expected '{'. */
/* @@? 110:5 Error SyntaxError: Unexpected token, expected '{'. */
/* @@? 165:1 Error SyntaxError: Expected '}', got 'eos'. */
