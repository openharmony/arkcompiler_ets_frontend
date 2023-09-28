function goo (i: int, p1: I1, s: String): void {}
function goo (i: int, p2: I5, s: String): void {}
function goo (i: int, p2: I2, s: String): void {}
interface I1 {}
interface I2 {}
interface I3 {}
interface I4 {}
interface I5 {}
class X implements I3, I2, I5, I1, I4 {}

function main (): void {
    goo (0, new X(), "ambiguous")
}
