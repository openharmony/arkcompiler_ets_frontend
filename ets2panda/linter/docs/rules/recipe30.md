#  Structural typing is not supported

Rule ``arkts-no-structural-typing``

**Severity: error**

Currently, ArkTS does not support structural typing, i.e., the compiler
cannot compare public APIs of two types and decide whether such types are
identical. Use other mechanisms (inheritance, interfaces or type aliases)
instead.


## TypeScript


```

    interface I1 {
        f(): string
    }

    interface I2 { // I2 is structurally equivalent to I1
        f(): string
    }

    class X {
        n: number = 0
        s: string = ""
    }

    class Y { // Y is structurally equivalent to X
        n: number = 0
        s: string = ""
    }

    let x = new X()
    let y = new Y()

    console.log("Assign X to Y")
    y = x

    console.log("Assign Y to X")
    x = y

    function foo(x: X) {
        console.log(x.n, x.s)
    }

    // X and Y are equivalent because their public API is equivalent.
    // Thus the second call is allowed:
    foo(new X())
    foo(new Y())

```

## ArkTS


```

    interface I1 {
        f(): string
    }

    type I2 = I1 // I2 is an alias for I1

    class B {
        n: number = 0
        s: string = ""
    }

    // D is derived from B, which explicitly set subtype / supertype relations:
    class D extends B {
        constructor() {
            super()
        }
    }

    let b = new B()
    let d = new D()

    console.log("Assign D to B")
    b = d // ok, B is the superclass of D

    // An attempt to assign b to d will result in a compile-time error:
    // d = b

    interface Common {
       n: number
       s: string
    }

    // X implements interface Z, which makes relation between X and Y explicit.
    class X implements Common {
        n: number = 0
        s: string = ""
    }

    // Y implements interface Z, which makes relation between X and Y explicit.
    class Y implements Common {
        n: number = 0
        s: string = ""
    }

    let x: Common = new X()
    let y: Common = new Y()

    console.log("Assign X to Y")
    y = x // ok, both are of the same type

    console.log("Assign Y to X")
    x = y // ok, both are of the same type

    function foo(c: Common): void {
        console.log(c.n, c.s)
    }

    // X and Y implement the same interface, thus both calls are allowed:
    foo(new X())
    foo(new Y())

```


