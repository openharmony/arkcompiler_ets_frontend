class X  {
    public foo: number
    private s: string

    constructor (f: number) {
        this.foo = f
        this.s = ""
    }

    public say(): void {
       console.log("X = ", this.foo)
    }
}

class Y {
    public foo: number

    constructor (f: number) {
        this.foo = f
    }
    public say(): void {
        console.log("Y = ", this.foo)
    }
}

function bar(z: X): void {
    z.say()
}

bar(new X(1))
bar(new Y(2) as X)