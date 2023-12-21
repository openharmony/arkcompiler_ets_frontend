const str1 = 'a';

enum T {
  A = 'aaa',
  B = 'bbb'
}

let obj: Record<string, number> = {
  ['b']: 123,
  [T.A]: 234,
  [T.B]: 345
};

let obj2: Record<string, number> = {
  [str1]: 111, // error
};

class A {
  ['b']: 123;
  [T.A]: 345;
  [T.B]: 456;
  [str1]: 234; // error
};
