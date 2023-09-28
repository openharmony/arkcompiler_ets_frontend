interface A<T>{
    foo(a0: T): void;
}

class B<U extends A<Object>>{
    private my_var: U;

    bar(): void {
        let a: Object = this.my_var;
    }
}
