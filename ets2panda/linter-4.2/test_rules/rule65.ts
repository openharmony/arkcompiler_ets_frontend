class X {
    // ...
}

let a = (new X()) instanceof Object // true
let b = (new X()) instanceof X      // true

let c = X instanceof Object // true, left operand is a type
let d = X instanceof X      // false, left operand is a type