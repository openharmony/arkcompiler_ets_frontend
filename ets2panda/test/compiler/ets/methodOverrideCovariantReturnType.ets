abstract class A {
    abstract foo(): A;
}

interface G {
    bar(): void;
}

class D extends A implements G{
    override foo(): D {
        return this;
    }
    override bar(): void {
        return;
    }
}

class C {

}

class B extends A {
    override foo(): D {
        let classD: D = new D();
        return classD;
    }
    foo(a: int): C {
        let classC: C = new C();
        return classC;
    }
}
