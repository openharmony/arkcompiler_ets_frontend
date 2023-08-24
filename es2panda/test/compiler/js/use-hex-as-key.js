let a = {
  0b1: 1,
  0o2: 2,
  0x3: 3,
  1e2: 100,
}
print(a[0b1])
print(a[0o2])
print(a[0x3])
print(a[1e2])
print(a[1])
print(a[2])
print(a[3])
print(a[100])

let b = {
  1: 1,
  2: 2,
  3: 3,
  100: 100,
}
print(b[1])
print(b[2])
print(b[3])
print(b[100])
print(b[0b1])
print(b[0o2])
print(b[0x3])
print(b[1e2])