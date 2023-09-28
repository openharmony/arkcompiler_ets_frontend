function main(): void {
    let a: byte = 2;
    let b: short = 20000;
    let c: int = 2000000;
    let d: long = 200000000000;
    let e: float = 2.2;
    let f: double = 2.2222222222;
    let g: double[] = [a, b, c, d, e, f];
    assert g[0] == 2;
    assert g[1] == 20000;
    assert g[2] == 2000000;
    assert g[3] == 200000000000;
    assert g[4] == (2.2 as float);
    assert g[5] == 2.2222222222;

    const h: byte = 2;
    const i: short = 2;
    const j: int = 2;
    const k: long = 2;
    const l: float = 2.0;
    const m: double = 2.0;
    const n: byte[] = [h, i, j, k, l, m];
    assert n[0] == 2;
    assert n[1] == 2;
    assert n[2] == 2;
    assert n[3] == 2;
    assert n[4] == 2;
    assert n[5] == 2;

    let o: Object[] = [1, 1.1, "testStr", new Int(2), d, k];
    assert (o[0] as Int) == 1;
    assert (o[1] as Double) == 1.1;
    assert (o[2] as String).equals("testStr");
    assert (o[3] as Int) == 2;
    assert (o[4] as Long) == 200000000000;
    assert (o[5] as Long) == 2;

    let p: long[] = [new Int(3), new Short(2 as short), new Long(4)];
    assert p[0] == 3;
    assert p[1] == 2;
    assert p[2] == 4;
}
