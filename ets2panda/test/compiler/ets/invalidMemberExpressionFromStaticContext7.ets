class A {
    final foo_in_A() : void {}
    static static_foo_in_A() : void {}
}

final class B extends A {
    static bar_in_B() : void {
        A.foo_in_A()
    }
}
