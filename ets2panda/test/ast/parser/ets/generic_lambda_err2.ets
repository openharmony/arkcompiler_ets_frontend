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

function main() {
    let foo1 = <T>(p: T): T => p;
    foo1("1", 2)
    foo1<int, string>("1", 2)

    let foo2 = <T>(p: T): T! =>p;

    let foo3 = <T, T>(p: T): T => p;

    let foo4 = <T, U>(p: T, q: U): T => p;
    foo4(1)
    foo4<int, string>(1)
    foo4<int, string>(1, 1)
}

/* @@? 18:5 Error TypeError: Expected 1 arguments, got 2. */
/* @@? 18:5 Error TypeError: No matching call signature for ("1", int) */
/* @@? 19:5 Error TypeError: Expected 1 type arguments, got 2 . */
/* @@? 19:5 Error TypeError: No matching call signature for ("1", int) */
/* @@? 21:32 Error TypeError: Type 'T' is not compatible with the enclosing method's return type 'NonNullable<T>' */
/* @@? 23:20 Error TypeError: Duplicate type parameter 'T'. */
/* @@? 26:5 Error TypeError: Expected 2 arguments, got 1. */
/* @@? 26:5 Error TypeError: No matching call signature for (int) */
/* @@? 27:5 Error TypeError: Expected 2 arguments, got 1. */
/* @@? 27:5 Error TypeError: No matching call signature for (int) */
/* @@? 28:5 Error TypeError: No matching call signature for (int, int) */
/* @@? 28:26 Error TypeError: Type 'int' is not compatible with type 'String' at index 2 */
