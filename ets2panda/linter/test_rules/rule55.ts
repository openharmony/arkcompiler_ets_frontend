let a = +5        // 5 as number
let b = +"5"      // 5 as number
let c = -5        // -5 as number
let d = -"5"      // -5 as number
let e = ~5        // -6 as number
let f = ~"5"      // -6 as number
let g = +"string" // NaN as number

function returnTen(): string {
    return "-10"
}

function returnString(): string {
    return "string"
}

let x = +returnTen()    // -10 as number
let y = +returnString() // NaN