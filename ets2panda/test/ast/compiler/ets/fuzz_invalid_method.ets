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

function foo<T>(this:A<T>, p: T): T {
    return this.data;
}

class A<T> {
    data: T
    constructor(p: T) {
        this.data = p;
    }
    goo1(): T {
        return this.foo(this.data);
    }

    goo
        return this./* @@ label */classVal;
    
(): T {
        return foo(this, this.data);
    }

}

/* @@? 30:9 Error SyntaxError: Unexpected token 'return'. */
/* @@? 30:9 Error SyntaxError: Field type annotation expected. */
/* @@? 30:16 Error SyntaxError: Unexpected token 'this'. */
/* @@? 30:20 Error SyntaxError: Unexpected token '.'. */
/* @@? 30:43 Error SyntaxError: Field type annotation expected. */
/* @@? 32:1 Error SyntaxError: Unexpected token '('. */
/* @@? 32:2 Error SyntaxError: Unexpected token ')'. */
/* @@? 32:3 Error SyntaxError: Unexpected token ':'. */
/* @@? 32:7 Error SyntaxError: Field type annotation expected. */
/* @@? 32:7 Error SyntaxError: Unexpected token '{'. */
/* @@? 33:9 Error SyntaxError: Unexpected token 'return'. */
/* @@? 33:19 Error TypeError: Only abstract or native methods can't have body. */
/* @@? 33:24 Error SyntaxError: The function parameter 'this' must explicitly specify the typeAnnotation. */
/* @@? 33:30 Error SyntaxError: The function parameter 'this' must explicitly specify the typeAnnotation. */
/* @@? 33:30 Error SyntaxError: Unexpected token, expected ',' or ')'. */
/* @@? 33:30 Error SyntaxError: Unexpected token '.'. */
/* @@? 33:31 Error TypeError: Variable 'data' has already been declared. */
/* @@? 33:35 Error SyntaxError: Field type annotation expected. */
/* @@? 33:35 Error SyntaxError: Unexpected token ')'. */
/* @@? 36:1 Error SyntaxError: Unexpected token '}'. */
