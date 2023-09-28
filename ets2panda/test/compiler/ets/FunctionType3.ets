let func: (a: int, b: int) => void;

function func2(): (a: int, b: int) => void {
    return func;
}

function main(): void {
    func2()(1, "foo");
}
