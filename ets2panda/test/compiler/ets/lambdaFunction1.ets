let a: int = 1;

let lambda1: () => int = (): int => {
    a++;
    return a;
}

function foo(a: (a: int, b: int) => int): int {
    let value = a(1, 2);
    value++;
    return value;
}

class A {
    bar(): int {
        return foo(this.a);
    }

    a: (a: int, b: int) => int = (a: int, b: int): int => {
        return a + b;
    }
}

function main(): void {
    let a = new A();
    let value = a.bar();
    value++;
}

