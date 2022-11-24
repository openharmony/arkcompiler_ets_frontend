{
    let a = 3;
    let b = [];

    for (let i = 0; i < a; i++) {
        let j = i;
        b.push(() => {
            print(i, j, a);
        });
    }

    b.forEach(f => f());
}