class B<T extends Object> {
    private a0: T;
    public f1(): T {
        return this.a0;
    }
}

class A {
    public foo(token: Object) : void {
        let refToken: B<Object> = this.f2() as B<Object>;
    }
    private bar() : void {
        let ref: B<Object> = this.f2() as B<Object>;
        if (ref.f1() == null) {}
    }

    private f2() : Object { return new Object(); }
}
