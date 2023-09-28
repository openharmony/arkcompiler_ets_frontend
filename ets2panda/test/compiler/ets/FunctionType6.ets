class A {
  foo(a: int): void {

  }
}

class B extends A {
  cb = super.foo;
}
