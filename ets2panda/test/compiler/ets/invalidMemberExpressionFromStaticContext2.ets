class A {
    final foo_in_A() : void {}
    static static_foo_in_A() : void {}

    static bar_in_A(arg: A) : void {
        this.foo_in_A()
    }
}
