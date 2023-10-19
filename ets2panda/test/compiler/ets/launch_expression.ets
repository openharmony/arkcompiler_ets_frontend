let count = 2
let n = 9
let a: int[] = new int[count];
let v: int[] = new int[count];
function assert_eq(value1: int, value2: int): void {
    if (value1 == value2) {
        return;
    }
    console.println("Values of type int are not equal: " + value1 + " != " + value2);
    throw new Error();
}
function ufib(n: int) : Int {
    if (n >= 0 && n < count) {
        return v[n];
    }
    let p: Promise<Int>[] = new Promise<Int>[count]
    for (let i = 0; i < count; ++i) {
        p[i] = launch ufib(n-1-i);
    }
    let result = 0
    for (let i = 0; i < count; ++i) {
        result = result + p[i].awaitResolution() * a[i];
    }
    return result;
}
function ufib_seq(n: int) : int {
    if (n >= 0 && n < count) {
        return v[n];
    }
    let result = 0
    for (let i = 0; i < count; ++i) {
        result = result + ufib_seq(n-1-i) * a[i];
    }
    return result;
}
export function main(): int {
    a[0] = 2;
    v[0] = 6;
    a[1] = 2;
    v[1] = 7;
    let seq_result = ufib_seq(n);
    let p = launch ufib(n);
    let co_result = p.awaitResolution();
    assert_eq(co_result as int, seq_result);
    return 0;
}