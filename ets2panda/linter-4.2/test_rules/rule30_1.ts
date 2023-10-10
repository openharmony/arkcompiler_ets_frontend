class X {
    public foo: number

    constructor() {
        this.foo = 0
    }
}

class Y {
    public foo: number

    constructor() {
        this.foo = 0
    }
}

let x = new X()
let y = new Y()

console.log("Assign X to Y")
y = x

console.log("Assign Y to X")
x = y