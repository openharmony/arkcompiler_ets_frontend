function returnTrue(): Boolean {
    return true;
}

function returnRefBool(a: boolean): Boolean {
    return a;
}

function main(): void {
    let a: Boolean = false;

    let b: Boolean = a || returnTrue();
    assert b == true

    let c: Boolean = returnRefBool(a || returnRefBool(returnTrue() && returnRefBool(a)));
    assert c == false

}
