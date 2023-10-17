#  Object literal must correspond to some explicitly declared class or interface

Rule ``arkts-no-untyped-obj-literals``

**Severity: error**

ArkTS supports usage of object literals if the compiler can infer to what
classes or interfaces such literals correspond to. A compile-time error
occurs otherwise. Using literals to initialize classes and interfaces is
specifically not supported in the following contexts:

* Initialization of anything that has ``any``, ``Object``, or ``object`` type
* Initialization of classes or interfaces with methods
* Initialization of classes which declare a ``constructor`` with parameters
* Initialization of classes with ``readonly`` fields


## TypeScript


```

    let o1 = {n: 42, s: "foo"}
    let o2: Object = {n: 42, s: "foo"}
    let o3: object = {n: 42, s: "foo"}

    let oo: Object[] = [{n: 1, s: "1"}, {n: 2, s: "2"}]

    class C2 {
        s: string
        constructor(s: string) {
            this.s = "s =" + s
        }
    }
    let o4: C2 = {s: "foo"}

    class C3 {
        readonly n: number = 0
        readonly s: string = ""
    }
    let o5: C3 = {n: 42, s: "foo"}

    abstract class A {}
    let o6: A = {}

    class C4 {
        n: number = 0
        s: string = ""
        f() {
            console.log("Hello")
        }
    }
    let o7: C4 = {n: 42, s: "foo", f : () => {}}

    class Point {
        x: number = 0
        y: number = 0
    }

    function id_x_y(o: Point): Point {
        return o
    }

    // Structural typing is used to deduce that p is Point:
    let p = {x: 5, y: 10}
    id_x_y(p)

    // A literal can be contextually (i.e., implicitly) typed as Point:
    id_x_y({x: 5, y: 10})

```

## ArkTS


```

    class C1 {
        n: number = 0
        s: string = ""
    }

    let o1: C1 = {n: 42, s: "foo"}
    let o2: C1 = {n: 42, s: "foo"}
    let o3: C1 = {n: 42, s: "foo"}

    let oo: C1[] = [{n: 1, s: "1"}, {n: 2, s: "2"}]

    class C2 {
        s: string
        constructor(s: string) {
            this.s = "s =" + s
        }
    }
    let o4 = new C2("foo")

    class C3 {
        n: number = 0
        s: string = ""
    }
    let o5: C3 = {n: 42, s: "foo"}

    abstract class A {}
    class C extends A {}
    let o6: C = {} // or let o6: C = new C()

    class C4 {
        n: number = 0
        s: string = ""
        f() {
            console.log("Hello")
        }
    }
    let o7 = new C4()
    o7.n = 42
    o7.s = "foo"

    class Point {
        x: number = 0
        y: number = 0

        // constructor() is used before literal initialization
        // to create a valid object. Since there is no other Point constructors,
        // constructor() is automatically added by compiler
    }

    function id_x_y(o: Point): Point {
        return o
    }

    // Explicit type is required for literal initialization
    let p: Point = {x: 5, y: 10}
    id_x_y(p)

    // id_x_y expects Point explicitly
    // New instance of Point is initialized with the literal
    id_x_y({x: 5, y: 10})

```

## See also

- Recipe 040:  Object literals cannot be used as type declarations (``arkts-no-obj-literals-as-types``)
- Recipe 043:  Array literals must contain elements of only inferrable types (``arkts-no-noninferrable-arr-literals``)


