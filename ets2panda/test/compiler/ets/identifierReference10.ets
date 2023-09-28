class B {
  a: int = 2;
}

class A {
  a: B = new B();

  bar(): void {
    this.a.a = "foo";
  }
}
