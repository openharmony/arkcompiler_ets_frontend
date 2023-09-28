class SomeObject {}

type SomeConstructor = {
    new (s: string): SomeObject
}

function fn(ctor: SomeConstructor) {
    return new ctor("hello")
}


class SomeObject2 {
    public f: string
    constructor (s: string) {
        this.f = s
    }
}

function foo(s: string): SomeObject {
    return new SomeObject2(s)
}