{
    let a = 3;
    let b = [];

    for (let i = 0; i < a; i++) {
        b.push(() => {
            print(i, a);
        });
    }

    b.forEach(f => f());
}
