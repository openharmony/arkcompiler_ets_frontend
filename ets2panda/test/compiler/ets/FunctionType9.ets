
class A {
  foo(a: int): void {

  }

  private cb: (a: int) => void = foo;
}

function main(): void {
  let instance = new A();
  instance.cb(1);
}

