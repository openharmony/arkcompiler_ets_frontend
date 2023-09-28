let a: int  = 1;

class B {
  a: String;
}

class A extends B {
  foo(): void {
    a = 12;
  }
}
