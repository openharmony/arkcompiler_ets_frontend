//test for defect 14030
type ESObject = any

let a1: ESObject = 1;
let a2: ESObject;

function foo() {
  let a3: ESObject  =2;
  let a4: ESObject;
}