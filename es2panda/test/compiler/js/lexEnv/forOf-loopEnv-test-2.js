{
    let a = [1, 2, 3];
    let b = [];

    for (let i of a) {
        let j = i;
        b.push(() => {
            print(j, a);
        });
    }

    b.forEach(f => f());
}