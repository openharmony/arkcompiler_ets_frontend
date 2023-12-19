class A {
    foo(p: Object[]): int {
        let s = 0
        for (let v of p) {
            s += v instanceof A ? 1 : 0
        }
        return s
    }
    bar(p: A[]): int {
        let s = 0
        for (let v of p) {
            s += v instanceof A ? 1 : 0
        }
        return s
    }
}


class B extends A{}

function main() {
    assert new A().foo([new Object(), new Long(), new Int()]) == 0
    assert new A().foo([new A(), new A(), new Object()]) == 2
    assert new A().foo(["aaa", new A(), new Object()]) == 1
    assert new A().foo([1, "hello", new A()]) == 1
    assert new A().bar([new B(), new B(), new A()]) == 3
}
