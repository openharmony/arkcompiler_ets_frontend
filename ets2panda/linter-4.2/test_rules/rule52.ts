// bad

class C1 {
  foo1() {
    console.log("foo");
  }
}

function bar1() {
  console.log("bar");
}

let c11 = new C1();
let c12 = new C1();
c12.foo1 = bar;

c11.foo1(); // foo
c12.foo1(); // bar

// good

class C {
  foo() {
    console.log("foo");
  }
}

class Derived extends C {
  foo() {
    console.log("Extra");
    super.foo();
  }
}

function bar() {
  console.log("bar");
}

let c1 = new C();
let c2 = new C();
c1.foo(); // foo
c2.foo(); // foo

let c3 = new Derived();
c3.foo(); // Extra foo
