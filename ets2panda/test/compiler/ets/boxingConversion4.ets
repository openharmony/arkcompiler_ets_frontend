function refInt(a: Int): void {}

function main() : void {
    let a: Short = new Short(3); // 3 is int, invocation context won't allow primitive narrowing
    let b: short = 2;
    let c: short = -b; // due to unary operator promotion, '-b' will be int, which is not assignable
    let d: short = b | b; // due to binary operator promotion, 'b | b' will be int, which is not assignable
    refInt(b); // primitive widening before boxing is not allowed
}
