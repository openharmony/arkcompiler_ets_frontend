class A {
    a: int = 1;
}

class B extends A {
    static {
        super.a = 13;
    }
}
