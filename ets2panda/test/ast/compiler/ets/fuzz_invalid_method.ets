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
    goo
        return this./* @@ label */classVal;
    
(): T {
        return foo(this, this.data);
    }

}

/* @@? 22:8 Error SyntaxError: Field type annotation expected. */
/* @@? 23:9 Error SyntaxError: Unexpected token 'return'. */
/* @@? 23:16 Error SyntaxError: Unexpected token 'this'. */
/* @@? 23:20 Error SyntaxError: Unexpected token '.'. */
/* @@? 23:43 Error SyntaxError: Field type annotation expected. */
/* @@? 25:1 Error SyntaxError: Unexpected token '('. */
/* @@? 25:2 Error SyntaxError: Unexpected token ')'. */
/* @@? 25:3 Error SyntaxError: Unexpected token ':'. */
/* @@? 25:6 Error SyntaxError: Field type annotation expected. */
/* @@? 25:7 Error SyntaxError: Unexpected token '{'. */
/* @@? 26:9 Error SyntaxError: Unexpected token 'return'. */
/* @@? 26:19 Error TypeError: Only abstract or native methods can't have body. */
/* @@? 26:24 Error SyntaxError: The function parameter 'this' must explicitly specify the typeAnnotation. */
/* @@? 26:30 Error SyntaxError: Unexpected token, expected ',' or ')'. */
/* @@? 26:30 Error SyntaxError: Unexpected token '.'. */
/* @@? 26:30 Error SyntaxError: The function parameter 'this' must explicitly specify the typeAnnotation. */
/* @@? 26:31 Error TypeError: Variable 'data' has already been declared. */
/* @@? 26:31 Error TypeError: Property 'data' must be accessed through 'this' */
/* @@? 26:35 Error SyntaxError: Field type annotation expected. */
/* @@? 26:35 Error SyntaxError: Unexpected token ')'. */
/* @@? 29:1 Error SyntaxError: Unexpected token '}'. */
