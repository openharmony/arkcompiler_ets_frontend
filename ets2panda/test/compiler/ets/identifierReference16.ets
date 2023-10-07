class B {
  foo(a: int): void {

  }
}

class C {

}

class A extends B {
  foo(a: int, b: int): void {

  }

  foo(): void {

  }

  class D extends C {
    foo(): void {

    }

    baz(): void {
      this.foo(1);
    }
  }
}
