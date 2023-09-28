function primInt(a: int): void {

}

function retRefShort(a: short): Short {
    return new Short(a);
}

function main(): void {
    let a: Byte = 2;
    let b: Short = 2;
    let c: Char = 2;
    primInt(a);
    primInt(b);
    primInt(c);
    let d: int = retRefShort(b);
    let e: double = retRefShort(b);
}
