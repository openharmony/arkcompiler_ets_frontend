class Klass {
    private a: int = 1;
    b: int = 2;
}

function main(): void {
    let klass: Klass = new Klass();
    let b = klass.b;
    let a = klass.a;
}
