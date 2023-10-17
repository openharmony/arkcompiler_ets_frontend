let a = [{n: 1, s: "1"}, {n: 2, s : "2"}]

class C {
    n: number = 0
    s: string = ""
}

let a1 = [{n: 1, s: "1"} as C, {n: 2, s : "2"} as C]
let a2: C[] = [{n: 1, s: "1"}, {n: 2, s : "2"}]