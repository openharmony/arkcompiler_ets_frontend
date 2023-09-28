let results : int[] = [0,0,0];
let index : int = 0;

class A {
    constructor() {
        results[index++] = 1;
    }
}

class B extends A {
    constructor() {
        super();
        results[index++] = 2;
    }
}

class C extends B {
    constructor() {
        results[index++] = 3;
    }
}

final class D extends C {}

function main() : void {
    results = [0, 0, 0];
    index = 0;

    let a = new A();
    assert (results[0] == 1 && results[1] == 0 && results[2] == 0 && index == 1);

    results = [0,0,0,0];
    index = 0;
    let b = new B();
    assert (results[0] == 1 && results[1] == 2 && results[2] == 0 && index == 2);

    results = [0,0,0,0];
    index = 0;
    let c = new C();
    assert (results[0] == 1 && results[1] == 2 && results[2] == 3 && index == 3);

    results = [0,0,0,0];
    index = 0;
    let d = new D();
    assert (results[0] == 1 && results[1] == 2 && results[2] == 3 && index == 3);
}
