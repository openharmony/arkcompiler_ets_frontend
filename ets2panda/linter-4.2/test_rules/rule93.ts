function foo(i: number) {
    this.count = i // Compile-time error only with noImplicitThis
}

class A {
    count: number = 1
    m = foo
}

let a = new A()
console.log(a.count) // prints "1"
a.m(2)
console.log(a.count) // prints "2"

class A1 {
    count: number = 1
    m(i: number): void {
        this.count = i
    }
}

function main(): void {
    let a = new A1()
    console.log(a.count)  // prints "1"
    a.m(2)
    console.log(a.count)  // prints "2"
}
