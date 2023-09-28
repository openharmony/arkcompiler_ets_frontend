class A {
    foo() {}
    bar() {}
}

function getSomeObject() {
    return new A()
}

let obj: any = getSomeObject()
if (obj && obj.foo && obj.bar) {
    console.log("Yes")  // prints "Yes" in this example
} else {
    console.log("No")
}