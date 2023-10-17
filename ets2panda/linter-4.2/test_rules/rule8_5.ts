function foo(p1: unknown) {
   console.log(p1);
}

function bar() {
  let fooVar: unknown = undefined;
}

foo("");
bar();
