class A {
  internal protected x : int;
  internal protected y : int;

  internal protected constructor(x: int, y: int) {
    this.x = x;
    this.y = y;
  }

  constructor(x: int){
    this(x, 42);
  }

  internal protected foo(): void {}
}

function main(): void {
  let instance : A = new A(2);
}