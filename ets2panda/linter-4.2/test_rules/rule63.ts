enum E { E1, E2 }

let a = 10 + 32   // 42
let b = E.E1 + 10 // 10
let c = 10 + "5"  // "105"

let d = "5" + E.E2 // "51"
let e = "Hello, " + "world!" // "Hello, world!"
let f = "string" + true // "stringtrue"

let g = (new Object()) + "string" // "[object Object]string"

let i = true + true // JS: 2, TS: compile-time error
let j = true + 2 // JS: 3, TS: compile-time error
let k = E.E1 + true // JS: 1, TS: compile-time error