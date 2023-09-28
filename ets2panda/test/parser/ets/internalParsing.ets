class A {
  internal x : int;
  internal y : int;

  internal constructor(x : int, y : int) {
    this.x = x;
    this.y = y;
  }
  
  internal foo(): void {}
}

function main(): void {
  let instance : A = new A(2, 3);
}
