interface A {
    bar(): void;
}

abstract class B implements A {
    override bar(): void{

    }
    abstract foo(): void;
    abstract foo(a: int): void;
    foo(b: double): void{

    }
}

class C extends B {
    override foo(): void {

    }
    override foo(a: int): void {

    }
}
