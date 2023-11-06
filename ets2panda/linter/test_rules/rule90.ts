    // Compile-time error with noImplicitAny
    function f(x: number) {
        if (x <= 0) {
            return x
        }
        return g(x)
    }

    // Compile-time error with noImplicitAny
    function g(x: number) {
        return f(x - 1)
    }

    function doOperation(x: number, y: number) {
        return x + y
    }

    console.log(f(10))
    console.log(doOperation(2, 3))

    function f1(x: number) : number {
        if (x <= 0) {
            return x
        }
        return g1(x)
    }

    function g1(x: number) {
        return f1(x - 1)
    }

    function doOperation1(x: number, y: number) {
        return x + y
    }

    console.log(f1(10))
    console.log(doOperation1(2, 3))
