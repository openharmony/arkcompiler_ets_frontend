function main(): void {
    for (let i = 0, j = 0; i < 10; ++i, j += 2) {
        let x = i + j;
        x = (++x, x++);
        console.println(x);
    }
}
