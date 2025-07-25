/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

interface I {}

class A {}
class B extends A implements I {}
final class C extends A implements I {}
final class D extends A {}
final class F extends B {}

function foo(p: Object): int {
  return 1;
}

function foo(p: A): int {
  return 2;
}

function foo(p: B): int {
  return 3;
}

function foo(p: C): int {
  return 4;
}

function foo(p: D): int {
  return 5;
}

function foo(p: F): int {
  return 6;
}

function getTrue(): boolean {
  return true
}

// #15276 foo(Object|null) and foo(Object) overloads
function foo7(p: Object | null): int {
    return 7;
}  

function main(): void {
    sameTypeLUB();
    objectLUB();
    forkSubtypeLUB();
}

function sameTypeLUB(): void {
    let a : A = new A();
    let b : A = new A();
    let c = getTrue() ? a : b;
    assertEQ(foo(c), 2)
}

function objectLUB(): void {
    let a : A = new A();
    let b : Int = 2;
    let c = getTrue() ? a : b;
    assertEQ(foo(c), 1)

    let arr : Int[] | null = null;
    let d = getTrue() ? a : arr;
    assertEQ(foo7(d), 7)
}

function forkSubtypeLUB(): void {
    let a : F = new F();
    let b : D = new D();
    let c = getTrue() ? a : b;
    assertEQ(foo(c), 2)
    let d : A = new A();
    let e = getTrue() ? a : b;
    assertEQ(foo(e), 2)
    let f : B = new B();
    let g = getTrue() ? a : f;
    assertEQ(foo(g), 3)
}
