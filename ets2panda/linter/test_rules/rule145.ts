class C {
    n: number // Compile-time error only with strictPropertyInitialization
    s: string // Compile-time error only with strictPropertyInitialization
}

// Compile-time error only with noImplicitReturns
function foo(s: string): string {
    if (s != "") {
        console.log(s)
        return s
    } else {
        console.log(s)
    }
}

let n: number = null // Compile-time error only with strictNullChecks