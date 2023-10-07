class A {
  foo(a: int): void {

  }

  foo(): void {

  }

  class B {
    foo(a: int): void {

    }

    baz(): void {
      this.foo();
    }
  }
}
