let [one, two] = [1, 2];
[one, two] = [two, one]

let head, tail
[head, ...tail] = [1, 2, 3, 4]

let arr2: number[] = [1, 2]
let one2 = arr2[0]
let two2 = arr2[1]

let tmp = one
one = two
two = tmp

let data2: Number[] = [1, 2, 3, 4]
let head2 = data2[0]
let tail2: Number[] = []
for (let i = 1; i < data2.length; ++i) {
    tail.push(data2[i])
}