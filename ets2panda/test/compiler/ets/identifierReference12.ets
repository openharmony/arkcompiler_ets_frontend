class B {
  foo: int = 12;
}

class A {
  b: B = new B();

  bar(): void {
    let a = this.b.foo();
  }
}
