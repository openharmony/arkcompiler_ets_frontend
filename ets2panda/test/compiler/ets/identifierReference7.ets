
class C {
  a: Object;
}

class A {
  a: int = 2;

  class B extends C {
    foo(): void {
      this.a++;
    }
  }
}
