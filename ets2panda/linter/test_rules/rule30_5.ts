interface Z {
    foo: number;
}


 // X implements interface Z, which makes relation between X and Y explicit.
class C implements Z {
     public foo: number
     public bar: string;

     constructor() {
        this.foo = 0
        this.bar = "Class C";
     }
 }

 // Y implements interface Z, which makes relation between X and Y explicit.
 class C2 implements Z {
     public foo: number;
     public bar: boolean

     constructor() {
        this.foo = 0;
        this.bar = true;
     }
 }

 let x1: Z = new C()
 let y1: Z = new C2()
 let x2 = new C()
 let y2 = new C2() 

console.log("Assign X to Y")
y2 = x2 // ok, both are of the same type

console.log("Assign X to Y")
y1 = x1 // ok, both are of the same type

console.log("Assign Y to X")
x1 = y1 // ok, both are of the same type
