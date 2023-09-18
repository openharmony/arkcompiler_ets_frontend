const a = "hello"
const a2 = "test"

let b = {
    [a]: 1,
    [a2]: 2
}

const {
    [a] : c,
    [a2]: d
} = b;

print(c);
print(d);