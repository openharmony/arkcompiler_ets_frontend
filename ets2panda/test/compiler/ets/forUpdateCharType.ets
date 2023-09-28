function main(): void {
  let mystring : String = "";

  for (let a: char = c'a'; a <= c'd'; a++) {
    mystring += a;
  }

  assert(mystring == "abcd");
}
