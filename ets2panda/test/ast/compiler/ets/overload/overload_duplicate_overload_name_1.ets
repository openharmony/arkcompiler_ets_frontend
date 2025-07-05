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

class Base {
    foo/* @@ label1 */(a: number) : string
    foo(a: string) : string
    overload /* @@ label2 */foo {/* @@ label3 */foo, /* @@ label4 */foo}
}

/* @@@ label1 Error TypeError: Only abstract or native methods can't have body. */
/* @@@ label2 Error TypeError: Variable 'foo' has already been declared. */
/* @@@ label3 Error TypeError: overloaded name must refer to an accessible method. */
/* @@@ label4 Error TypeError: Duplicate overloaded method. */
/* @@@ label4 Error TypeError: overloaded name must refer to an accessible method. */
