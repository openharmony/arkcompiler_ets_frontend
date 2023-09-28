class A {
    public readonly a: int;

    constructor() {
        this.a = 42;
    }
}

final class B extends A {

}

final class C extends A {
    constructor() {

    }
}

final class D extends A {
    constructor() {
        super();
    }
}


function main(): void {
    const a: A = new A();
    assert a.a == 42;

    const b: B = new B();
    assert b.a == 42;

    const c: C = new C();
    assert c.a == 42;

    const d: D = new D();
    assert d.a == 42;

    let d_as_A: A = d;
    assert d_as_A.a == 42;
}
