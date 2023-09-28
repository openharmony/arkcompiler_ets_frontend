abstract class A extends B implements C{
    foo(a: int): void {

    }
    abstract bar(b: boolean): void;
    foo(a: byte): int {
        return 2;
    }
    override func(a: int): void {

    }
}

interface D {
    foo(a: byte): int;
}

interface C {
    interf(a: int, b: int): void;
}

abstract class H {
    abstract func(a: int): void;
    test(a: int): void{

    }
}

abstract class B extends H {
    interf(a: int, b: int): void{

    }
}

interface F {
    test(a: int): void;
}

class G extends A implements D, F {
    override bar(a: boolean): void {

    }
}
