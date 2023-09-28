let func: (a: int, b:int) => void;

class Klass {
    a(a: int, b:int): int;
}

function main(): void {
    let klass: Klass = new Klass();
    func = klass.a;
}
