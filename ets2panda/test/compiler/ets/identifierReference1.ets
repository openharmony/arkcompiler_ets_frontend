let a:(a: int, b: int) => int = max;

let b: String = "foo";

function bar (a: int): void {

}

class B {
  b: int = 2;
  static c: (a: int) => void;
  foo(a: int): void {

  }
}

class A extends B {
  foo(a: int, b: int): void {
    b = 3;
  }

  static foo(): void {
    A.c = bar;
  }

  baz(): void {
    this.foo(1);
  }

  class C {
    foo(): void {
      this.b = 4;
    }
  }
}
