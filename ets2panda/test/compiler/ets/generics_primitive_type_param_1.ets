class A<T> {
    public value: T;
    public prim_value: int = 5;
}

function foo(a0: int): void {}

function test(): void {
    let a_int: A<int> = new A<int>();
    a_int.value = 2;
    foo(a_int.value);
    let v1 = a_int.value;
    let v2: int = a_int.value;
    let v3: boolean = v1 == 2;
    a_int.value = a_int.prim_value;

    let a_double: A<double> = new A<double>();
    a_double.value = 1.5;
    let v4 = a_double.value - 1.5;

    let a_boolean: A<boolean> = new A<boolean>();
    a_boolean.value = false;
    let v5 = a_boolean.value == false;
}
