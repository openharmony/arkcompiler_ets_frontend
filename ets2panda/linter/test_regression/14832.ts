enum T {
  A = 'a',
  B = 'b'
}

let obj: Record<string, number> = {
  [T.A]: 123,
  [T.B]: 456
};