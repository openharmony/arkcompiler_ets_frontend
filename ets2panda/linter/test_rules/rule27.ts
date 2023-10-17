interface I {
    new (s: string): I
}

function fn(i: I) {
    return new i("hello")
}

interface I2 {
    create(s: string): I
}

function foo(i: I2) {
    return i.create("hello")
}