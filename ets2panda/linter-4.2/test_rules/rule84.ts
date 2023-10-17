with (Math) { // Compile-time error, but JavaScript code still emitted
    let r: number = 42
    console.log("Area: ", PI * r * r)
}

let r: number = 42
console.log("Area: ", Math.PI * r * r)