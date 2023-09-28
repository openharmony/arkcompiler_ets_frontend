class A {
  foo(a: int): void {

  }
}

function main(): void {
  let instance = new A();
  let cb = instance.foo;
}
