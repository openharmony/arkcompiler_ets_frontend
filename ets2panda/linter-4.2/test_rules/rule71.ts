for (let i = 0, j = 0; i < 10; ++i, j += 2) {
    console.log(i)
    console.log(j)
}

let x = 0
x = (++x, x++)

for (let i = 0, j = 0; i < 10; ++i, j += 2) {
    console.log(i)
    console.log(j)
}

let x2 = 0
++x2
x2 = x2++

let c = () => 33;
const a = (1, b = 2, c());
const r = (c(), b, 1)

class Test {
    static readonly sr = (1, c(), 2);
    field1 = (1, 2, c());

    method() {
        this.field1 = (c(), sr, 1);
    }
}
