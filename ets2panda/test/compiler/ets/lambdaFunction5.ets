class A {
    c = 1;

    a: (a: int, b: int) => int = (a: int, b:int): int => {
        return a + b + c;
    }

    foo(): (b: int, c: int) => int {
        return a;
    }

    foo(d: int): (b: int, c: int) => int {
        return a;
    }
}

function main(): void {
    let a = new A();
    a.foo()(1, 1);
    a.foo(1)(1, "foo");
}
