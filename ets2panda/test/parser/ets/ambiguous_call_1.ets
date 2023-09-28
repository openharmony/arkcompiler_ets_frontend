function goo (p1: I1): void {}
function goo (p2: I2): void {}
interface I1 {}
interface I2 {}
class X implements I1, I2 {}

function main (): void {
    goo (new X())
}
