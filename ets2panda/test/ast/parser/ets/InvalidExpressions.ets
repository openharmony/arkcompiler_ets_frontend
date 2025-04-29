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

function f1(a: int, ...b: int[] = 47): bool {
    console.log(a, b...);
    let x = (x instanceof A<string);
    return x instanceof A<int>;
}

function f2(a?: int = 44): void {}

function f3(a: int = ): void;

function f4() {
    55 = int;
    69++
    --58
    78 = type
}

function f5(...b: int[] = 47, c?: int = 88): void {}

let x = (: int => { return 7; }

let x: number => 77
let x = new int(7);
let x = new int{8};

interface C {
    f(a: int = 0): void;
}

class A {
    f1(): void {
        async x = 9
    }

    f2() {
        this.99++;
    }
}

function f6(a: int = 9 @@): void;

function f7(a: (b: int = 0) => int): void {
}

/* @@? 16:35 Error SyntaxError: Rest parameter cannot have the default value. */
/* @@? 16:37 Error SyntaxError: Identifier is needed here. */
/* @@? 16:40 Error TypeError: Cannot find type 'bool'. */
/* @@? 17:20 Error TypeError: Unresolved reference b */
/* @@? 17:21 Error SyntaxError: Unexpected token '...'. */
/* @@? 17:21 Error SyntaxError: Unexpected token, expected ',' or ')'. */
/* @@? 17:24 Error SyntaxError: Unexpected token ')'. */
/* @@? 18:13 Error TypeError: Bad operand type, the types of the operands must be numeric, same enumeration, or boolean type. */
/* @@? 18:13 Error TypeError: Circular dependency detected for identifier: x */
/* @@? 18:14 Error TypeError: Variable 'x' is accessed before it's initialization. */
/* @@? 18:35 Error SyntaxError: Unexpected token, expected '>'. */
/* @@? 18:36 Error SyntaxError: Unexpected token ';'. */
/* @@? 18:36 Error SyntaxError: Unexpected token, expected ')'. */
/* @@? 19:12 Error TypeError: Bad operand type, the types of the operands must be same type. */
/* @@? 19:25 Error Warning: Type parameter is erased from type 'A' when used in instanceof expression. */
/* @@? 22:23 Error SyntaxError: Not enable default value with default undefined. */
/* @@? 24:10 Error TypeError: Only abstract or native methods can't have body. */
/* @@? 24:22 Error SyntaxError: You didn't set the value. */
/* @@? 24:22 Error SyntaxError: Unexpected token ')'. */
/* @@? 27:5 Error TypeError: Invalid left-hand side of assignment expression */
/* @@? 27:8 Error SyntaxError: Invalid left-hand side in assignment expression. */
/* @@? 28:7 Error SyntaxError: Invalid left-hand side operator. */
/* @@? 30:5 Error TypeError: Invalid left-hand side of assignment expression */
/* @@? 30:5 Error SyntaxError: Invalid left-hand side in prefix operation. */
/* @@? 30:8 Error SyntaxError: Invalid left-hand side in assignment expression. */
/* @@? 33:27 Error SyntaxError: Rest parameter cannot have the default value. */
/* @@? 33:29 Error SyntaxError: Identifier is needed here. */
/* @@? 33:41 Error SyntaxError: Not enable default value with default undefined. */
/* @@? 35:10 Error SyntaxError: Unexpected token ':'. */
/* @@? 35:10 Error SyntaxError: Unexpected token, expected ')'. */
/* @@? 35:12 Error SyntaxError: Unexpected token 'int'. */
/* @@? 35:16 Error SyntaxError: Unexpected token '=>'. */
/* @@? 37:5 Error TypeError: Variable 'x' has already been declared. */
/* @@? 37:15 Error SyntaxError: Unexpected token '=>'. */
/* @@? 38:5 Error TypeError: Variable 'x' has already been declared. */
/* @@? 38:9 Error TypeError: This expression is not constructible. */
/* @@? 39:5 Error TypeError: Variable 'x' has already been declared. */
/* @@? 39:9 Error TypeError: This expression is not constructible. */
/* @@? 39:16 Error SyntaxError: Unexpected token '{'. */
/* @@? 47:15 Error SyntaxError: Unexpected token, expected '('. */
/* @@? 47:17 Error SyntaxError: Unexpected token, expected an identifier. */
/* @@? 48:5 Error SyntaxError: Unexpected token, expected ',' or ')'. */
/* @@? 48:5 Error SyntaxError: Expected '=>', got '}'. */
/* @@? 48:5 Error SyntaxError: Unexpected token '}'. */
/* @@? 51:13 Error SyntaxError: Unexpected token '.99'. */
/* @@? 51:16 Error SyntaxError: Invalid left-hand side operator. */
/* @@? 55:10 Error TypeError: Only abstract or native methods can't have body. */
/* @@? 55:24 Error SyntaxError: Unexpected token '@@'. */
/* @@? 55:24 Error SyntaxError: Unexpected token, expected ',' or ')'. */
/* @@? 55:26 Error SyntaxError: Unexpected token ')'. */
/* @@? 55:27 Error SyntaxError: Unexpected token ':'. */
/* @@? 55:29 Error TypeError: Unresolved reference void */
/* @@? 57:26 Error SyntaxError: Default value is allowed only for optional parameters. */
