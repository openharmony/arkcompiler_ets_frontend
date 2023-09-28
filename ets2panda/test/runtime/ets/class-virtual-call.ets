class A {
    foo() : int {
        return 1;
    }
}

class B extends A {
    override foo() : int {
        return 2;
    }
}

function main() : void {
    let x : A = new A();
    assert (x.foo() == 1)

    let y : B = new B();
    assert (y.foo() == 2)

    let z : A = new B();
    assert (z.foo() == 2)
}
