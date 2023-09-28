function f() {}
function nn(x: int, y: int) {}

function main() {
    let fp: () => void = f
    let nnp: (a: int, b: int) => void = nn
    let o: Object = fp
    o = nnp
}
