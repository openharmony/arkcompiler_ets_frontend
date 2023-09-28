class A{}

function main(): void {
  ClassEquality();
  NullEquality();
  ArrayEquality();
}

function ClassEquality(): void {
    let a : A = new A();
    let b = a;
    assert (a === b);
    let c : A = new A();
    assert (a !== c);
}


function NullEquality(): void {
    let a : A | null = null;
    let b = a;
    assert (a === b);
    let c : A | null = null;
    assert (c === null);
    assert (null === null);
}


function ArrayEquality(): void {
    let a : int[] = [1, 2, 3];
    let b = a;
    assert (a === b);
    let c : int[] = [1, 2, 3];
    assert (a !== c);
}

function NumericEquality(): void {
    let a : Int = 1;
    let b = a;
    assert (a === b);
    let c : Int = 1;
    assert (a !== c);
    let d : Double = 1.0;
    assert (a !== c);
}
