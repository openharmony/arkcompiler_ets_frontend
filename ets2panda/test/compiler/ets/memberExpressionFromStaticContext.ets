class A {
    foo_in_A() : void {}
    static static_foo_in_A() : void {}

    static bar_in_A(arg: A) : void {
        arg.foo_in_A()
        A.static_foo_in_A()
    }
}

class B {
    foo_in_B() : void {}
    static static_foo_in_B() : void {}

    static bar_in_B(arg: A) : void {
        arg.foo_in_A()
        A.static_foo_in_A()
        B.static_foo_in_B();

        let b_instance = new B()
        b_instance.foo_in_B()
    }
}

class C extends A {
    foo_in_C() : void {}
    static static_foo_in_C() : void {}

    static bar_in_C(arg: A) : void {
        arg.foo_in_A()
        A.static_foo_in_A()
        C.static_foo_in_C();

        let c_instance = new C()
        c_instance.foo_in_C()
        c_instance.foo_in_A()
    }
}
