class Klass {
    public constructor() {
        this.a = 2;
    }

    private a: int = 1;

    private foo(): void {

    }

    public foo(a: int): void {

    }
}

function main(): void {
    let klass: Klass = new Klass();
    klass.foo(12);
    klass.foo();
}
