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