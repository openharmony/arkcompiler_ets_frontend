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

function foo(...^number: FixedArray<int>): int {
    return number[0]
}

/* @@? 16:10 Error TypeError: Only abstract or native methods can't have body. */
/* @@? 16:17 Error SyntaxError: Unexpected token, expected an identifier. */
/* @@? 16:18 Error SyntaxError: Parameter declaration should have an explicit type annotation. */
/* @@? 16:18 Error SyntaxError: Rest parameter must be the last formal parameter. */
/* @@? 16:41 Error SyntaxError: Unexpected token ')'. */
/* @@? 16:41 Error SyntaxError: Unexpected token ')'. */
/* @@? 16:42 Error SyntaxError: Unexpected token ':'. */
/* @@? 16:42 Error SyntaxError: Unexpected token ':'. */
/* @@? 16:44 Error SyntaxError: Unexpected token 'int'. */
/* @@? 16:44 Error SyntaxError: Unexpected token 'int'. */
/* @@? 17:5 Error SyntaxError: return keyword should be used in function body. */
/* @@? 17:12 Error TypeError: Type name 'number' used in the wrong context */
/* @@? 17:12 Error TypeError: Indexed access is not supported for such expression type. */
/* @@? 17:12 Error TypeError: All return statements in the function should be empty or have a value. */
