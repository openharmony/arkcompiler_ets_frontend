function foo(callback: (x: int, y: int) => int): void {
    let x: int = callback(2, 3);
}

function main(): void {
    foo((y) => {});
}
