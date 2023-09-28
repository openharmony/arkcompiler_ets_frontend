class Foo<T> {
    static resolve<U>(): Foo<U> {
        return new Foo<U>();
    }
}
