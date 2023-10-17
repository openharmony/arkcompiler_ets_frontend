
function f(shouldInitialize: boolean) {
    if (shouldInitialize) {
       var x = 10
    }
    return x
}

console.log(f(true))
console.log(f(false))

let upper_let = 0
{
    var scoped_var = 0
    let scoped_let = 0
    upper_let = 5
}
scoped_var = 5
scoped_let = 5