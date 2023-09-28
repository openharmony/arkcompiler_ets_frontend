function constantCases(): void{
    let a : char = 100;
    let first = true ? a : 68;

    let b : byte = 50;
    let sec = false ? b : 68;

    let c : Short = 721;
    let third = true ? c : 419;

    let d : char = 3;
    let fourth = false ? c : 665;

    let e : Byte = 88;
    let fifth = true ? c : 665;

    let f : short = 20;
    let sixth = true ? c : 665419;

    let g : double = 40;
    let seventh = false ? g : 30;
}

function unboxingCases(): void{
    let a : Char = c'k';
    let b : char = c'l';
    let first = true ? a : b;

    let c : Int = 11;
    let d : int = 10;
    let sec = false ? a : b;
}

function dominantNumericCases(): void{
    let a : double = 2.0;
    let b : float = 2.0;
    let c : long = 2;
    let d : int = 2;
    let e : Short = 2;
    let f : byte = 2;
    let g : char = 2;

    let first = false ? a : b;
    let sec = false ? b : c;
    let third = false ? c : d;
    let fourth = false ? d : e;
    let fifth = false ? e : f;
    let sixth = false ? f : g;
}

function main(): void {
    constantCases();
    unboxingCases();
    dominantNumericCases();
}
