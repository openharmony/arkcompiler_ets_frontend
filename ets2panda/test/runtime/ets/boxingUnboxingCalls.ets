function intParam(a: int): int {
    return 0;
}

function intParam(a: Int): int {
    return 1;
}

function objParam(a: Object): int {
    return 2;
}

function retRefInt(a: int): Int {
    return new Int(a);
}

function retInt(a: Int): int {
    return a;
}

function main(): void {
    let a: int = 1;
    let b: Int = 2;
    let c: int = intParam(a);
    assert c == 0
    let d: int = intParam(b);
    assert d == 1
    let e: Int = intParam(a);
    assert c == 0
    let f: Int = intParam(b);
    assert d == 1
    let g: int = objParam(a);
    assert g == 2
    let h: int = objParam(b);
    assert h == 2
    let i: Object = b;
    let j: int = retInt(retRefInt(5));
    assert j == 5
}
