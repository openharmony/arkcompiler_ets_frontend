let o: {x: number, y: number} = {
    x: 2,
    y: 3
}

type S = Set<{x: number, y: number}>

class C {
    x: number = 0
    y: number = 0
}

let c: C = {x: 2, y: 3}

type t = Set<C>