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

/*---
flags: [dynamic-ast]
---*/

import { A, I, Animal } from "dynamic_import_tests/modules/module"

let a = /* @@ label */new Animal() // CTE

class Bird extends Animal { // OK
    move(): void { }
}

class C extends A {
    override foo(p: double): string {
    } //ok
} // ok

let c = new C()
c.f1 // ok
C.f2 // ok
c./* @@ label1 */f3 // cte
c.foo(123) // ok
C.bar() // ok
c./* @@ label2 */foa() //cte

class C1 implements I { // ok
    s: string
    f1(p: string): double {
        return 12
    }
    f2(p: double): string {
        return ""
    }
}

function foo(i: I) {
    i.s // ok
    i./* @@ label3 */n // cte
    i.f1("") // ok
    i./* @@ label4 */f3() // cte
}

/* @@@ label Error TypeError: Animal is abstract therefore cannot be instantiated. */
/* @@@ label1 Error TypeError: Property 'f3' does not exist on type 'C' */
/* @@@ label2 Error TypeError: Property 'foa' does not exist on type 'C' */
/* @@@ label3 Error TypeError: Property 'n' does not exist on type 'I' */
/* @@@ label4 Error TypeError: Property 'f3' does not exist on type 'I' */