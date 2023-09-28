class A {}
class B extends A {}
class C extends B {}
class D extends C {}

function main(): void {
    let d : D = new D();
    let c : C = d;
    let b : B = d;
    let a : A = d;
    let o : Object = d;
}
