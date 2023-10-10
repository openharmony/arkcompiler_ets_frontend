interface Z {
    foo: number;
}

interface Z1 {
    bar: string;
}

 // X implements interface Z, which makes relation between X and Y explicit.
 class C implements Z, Z1 {
     public foo: number
     public bar: string;

     constructor() {
        this.foo = 0
        this.bar = "Class C";
     }
 }

 // Y implements interface Z, which makes relation between X and Y explicit.
 class C2 implements Z, Z1 {
     public foo: number;
     public bar: string;

     constructor() {
        this.foo = 0;
        this.bar = "Class C2";
     }
 }

 let x1: Z = new C()
 let y1: Z1 = new C2()

console.log("Assign X to Y")
y1 = x1 // ok, both are of the same type

console.log("Assign Y to X")
x1 = y1 // ok, both are of the same type
