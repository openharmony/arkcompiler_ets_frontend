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

class A<T> {
    prop: T;
}

function foo<T>(this: A<T>, p: T): T {
    this.prop = p;
    return this.prop;
}

function main() {
    let a1 = new A<Object>();
    assertEQ(foo<Object>(a1, new String("hello")), "hello")
    assertEQ(a1.foo<Object>(new String("hello")), "hello")

    let a2 = new A<Object>();
    let p = new Int(1);
    assertEQ(foo<Object>(a2, p), p)
    assertEQ(a2.foo<Object>(p), p)
}