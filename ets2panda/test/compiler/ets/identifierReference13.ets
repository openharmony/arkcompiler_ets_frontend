class B {
  foo(): void {}
}

class A {
  b: B = new B();

  bar(): void {
    let a = this.b.foo + 1;
  }
}
