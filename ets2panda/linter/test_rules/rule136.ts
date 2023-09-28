var C = function(p: number) {
    this.p = p // Compile-time error only with noImplicitThis
}

C.prototype = {
    m() {
        console.log(this.p)
    }
}

C.prototype.q = function(r: number) {
    return this.p == r
}