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

class A {}
class B extends A {}

function main() {
    let foo = <T extends U | undefined | null, U extends Object | undefined | null> (p: T, q: U): int => {
        if (p !== null && p !== undefined) {
            return 0;
        } else if (q !== null && q != undefined) {
            return 1;
        } else {
            return 2;
        }
    }

    // Explicitly deducing generics
    assertEQ(foo<Object, Object>(new Object(), new Object()), 0)
    assertEQ(foo<undefined, Object>(undefined, new Object()), 1)
    assertEQ(foo<undefined, undefined>(undefined, undefined), 2)
    assertEQ(foo<A, A>(new A(), new A()), 0)
    assertEQ(foo<B, A>(new B(), new A()), 0)
    assertEQ(foo<B, B>(new B(), new B()), 0)

    // Implicit derivation of generics
    assertEQ(foo(new Object(), new Object()), 0)
    assertEQ(foo(undefined, new Object()), 1)
    assertEQ(foo(undefined, undefined), 2)
    assertEQ(foo(new A(), new A()), 0)
    assertEQ(foo(new B(), new A()), 0)
    assertEQ(foo(new B(), new B()), 0)
}
