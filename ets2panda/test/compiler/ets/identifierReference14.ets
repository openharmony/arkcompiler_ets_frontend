
function foo(a: int): void {

}

class B {
  foo(): void {

  }
}

class A extends B {
  foo(a: int, b: int): void {

  }

  bar(): void {
    foo(1);
  }
}
