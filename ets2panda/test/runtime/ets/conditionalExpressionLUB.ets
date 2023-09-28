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

function main(): void {
    sameTypeLUB();
    objectLUB();
    forkSubtypeLUB();
}

function sameTypeLUB(): void {
    let a : A = new A();
    let b : A = new A();
    let c = true ? a : b; // A
    assert(foo(c) == 2);
}

function objectLUB(): void {
    let a : A = new A();
    let b : Int = 2;
    let c = true ? a : b; // Object
    assert(foo(c) == 1);

    let arr : Int[] | null = null;
    let d = true ? a : arr; // Object
    assert(foo(d) == 1);
}

function forkSubtypeLUB(): void {
    let a : F = new F();
    let b : D = new D();
    let c = true ? a : b; // A
    assert(foo(c) == 2);
    let d : A = new A();
    let e = true ? a : b; // A
    assert(foo(e) == 2);
    let f : B = new B();
    let g = true ? a : f; // B
    assert(foo(g) == 3);
}
