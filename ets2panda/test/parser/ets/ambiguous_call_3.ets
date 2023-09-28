function goo (p1: I1): void {}
function goo (p2: B): void {}
interface I1 {}
class B {}
class X extends B implements I1 {}

function main (): void {
    goo (new X())
}
