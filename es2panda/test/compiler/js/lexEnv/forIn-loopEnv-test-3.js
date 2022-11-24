{
    let a = [1, 2, 3];
    let b = [];

    for (let i in a) {
        let j = a[i];
        b.push(() => {
            print(i, j, a);
        });
    }

    b.forEach(f => f());
}