function check(): Boolean {
  assert false;
  return true;
}

function main(): void {
  let x: Boolean = false;
  assert !(x && check());

  let y: Char = c'a';
  assert (y != c'b');
}
