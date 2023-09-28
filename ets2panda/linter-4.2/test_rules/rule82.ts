let a: Set<number> = new Set([1, 2, 3])
for (let s of a) {
    console.log(s)
}

let numbers = Array.from(a.values())
for (let n of numbers) {
    console.log(n)
}