class Outer {
    class A {
        private a: int = 12;
    }

    class B {
        foo(): void {
            let a: A = new A();
            a.a = 13;
        }
    }
}


class C {
    private c: int = 12;
}

class D {
    foo(): void {
        let c: C = new C();
        c.c = 13;
    }
}
