
class B {
  foo(a: int, b:int): void {

  }

  cb: (a: int, b: int) => void = this.foo;
}

class A extends B {
  foo(a: int): void {

  }

  cb: (a: int) => void = this.foo;
}

function main(): void {
  let instance = new A();
  instance.cb(1);
  instance.cb(1, 2);
}
