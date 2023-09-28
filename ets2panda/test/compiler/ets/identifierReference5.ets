function bar(a: int): void {

}

class B {
  b: int = 2;
  c: (a: int) => void;
}

class A extends B {
  foo(): void {
    this.b = 3;
  }

  static foo(): void {
    this.c = bar;
  }
}
