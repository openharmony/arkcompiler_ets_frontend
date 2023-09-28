class A {}

function main(): int {
  classEquality();
  arrayEquality();
  functiontypeEquality();
  nullEquality();
  return 0;
}

function classEquality(): void {
  let a = new A;
  let b = a;
  assert (a == b);
  b = new A;
  assert (a != b);
}

function arrayEquality(): void {
  let a : int[] = null;
  let b = a;
  assert (a == b);
}

function functiontypeEquality(): void {
  let a : (x : double, y : double) : double;
  let b = a;
  assert (a == b);
}

function nullEquality(): void {
  let a = new A;
  let hit : int = 0;

  if (a == null) {
    assert(false);
  } else {
    hit = 1;
  }
  assert (hit == 1);

  if (a != null) {
    hit = 2;
  } else {
    assert(false);
  }
  assert (hit == 2);

  if (null == a) {
    assert(false);
  } else {
    hit = 3;
  }
  assert (hit == 3);

  if (null != a) {
    hit = 4;
  } else {
    assert(false);
  }
  assert (hit == 4);


  a = null;

  if (a != null) {
    assert(false);
  } else {
    hit = 1;
  }
  assert (hit == 1);

  if (a == null) {
    hit = 2;
  } else {
    assert(false);
  }
  assert (hit == 2);

  if (null != a) {
    assert(false);
  } else {
    hit = 3;
  }
  assert (hit == 3);

  if (null == a) {
    hit = 4;
  } else {
    assert(false);
  }
  assert (hit == 4);
}
