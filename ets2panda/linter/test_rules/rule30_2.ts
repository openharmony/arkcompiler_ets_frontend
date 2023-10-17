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




interface Z {
    foo: number
 }

 // X implements interface Z, which makes relation between X and Y explicit.
 class C implements Z {
     public foo: number

     constructor() {
        this.foo = 0
     }
 }

 // Y implements interface Z, which makes relation between X and Y explicit.
 class C2 implements Z {
     public foo: number

     constructor() {
        this.foo = 0
     }
 }

 let x1: Z = new C()
 let y1: Z = new C2()

 console.log("Assign X to Y")
 y1 = x1 // ok, both are of the same type

 console.log("Assign Y to X")
 x1 = y1 // ok, both are of the same type