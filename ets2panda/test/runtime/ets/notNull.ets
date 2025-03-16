/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
    testLocalIdentifier()
    testArgument()
    testCallExpression()
    testNPE()
    testFieldAccess()
    testFieldAccess2()
}

function typeOf(i : Int) : int {
    return 1;
}

function typeOf(o : Object) : int {
    return -1;
}

function dummy(): Int | null {
    return 5;
}

function testLocalIdentifier() : void {
    let a : Int | null = dummy();
    let b = a!;

    assertEQ(typeOf(b), 1,  "b must be type Int")
    assertEQ(b, 5, "b must be 5")

    let c = b + a! * 7;

    assertEQ(c, 40,  "c should be 40")

    assertEQ(a!, (a)!)
}

function bar(arg : Int | null) : Int {
    return arg!;
}

function testArgument() : void {
    let a : Int | null = 7;
    let b = bar(a);

    assertEQ(typeOf(b), 1,  "b must be type Int")
    assertEQ(b, 7)
}

function foo() : Double | null {
    return new Double(3.1415);
}

class Foo {
    foo() : Float | null {
        return Float.DELTA;
    }
}

function testCallExpression() {
    let d = foo()!

    assertTrue(d instanceof Double, "d must be type Double")
    assertEQ(d, 3.1415, "d must be 3.1415")

    let sd = foo()!.toString()

    assertTrue("3.1415".equals(sd), "s must be '3.1415'")

    let f = new Foo().foo()!

    assertTrue(f instanceof Float, "f must be type Float")
    assertEQ(f, Float.DELTA, "f must be Float.DELTA")
}

function baz() : Byte | null {
    return null;
}

function aux(): Object | null {
   return null;
}

function testNPE() : void {
    let o : Object | null = aux();
    let npe_caught = false;

    try {
        (o as Object | null)!;
        assertTrue(false, "this must not be executed")
    } catch (ex: NullPointerError) {
        npe_caught = true;
    }

    assertTrue(npe_caught, "NPE must be caught")

    try {
        baz()!;
        assertTrue(false, "this must not be executed")
    } catch (ex: NullPointerError) {
        npe_caught = true;
    }

    assertTrue(npe_caught, "NPE must be caught")
}

class A {
    public static c : Char | null = c'C';
    public d : Char | null = c'D'
}

class B {
    public a : A | null;

    constructor(a : A | null) {
        this.a = a;
    }

    public setA(a : A) {
        this.a = a;
    }

    public getA() : A {
        return this.a!;
    }
}

function testFieldAccess() : void {
    let ac = A.c!;
    assertEQ(ac, c'C', "ac should be 'C'")

    let a_orig = new A();
    let b = new B(a_orig);

    let a = b.a!;

    assertEQ(a, a_orig, "a should be the object referenced by a_orig")

    let d = b.a!.d!;

    assertEQ(d, c'D', "d should be 'D'")
}

function testFieldAccess2() : void {
    let a = new A();
    let b = new B(a);

    assertEQ(b.getA(), a, "getA should return the same object that was given to the constructor")

    let a2 = new A();
    b.setA(a2);

    assertEQ(b.getA(), a2, "getA should return the same object that was given to setA")
}
