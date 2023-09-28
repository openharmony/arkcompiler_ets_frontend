abstract class A {
    abstract foo(): void;
}

class H {

}

class B {
    bar: A = new A() {
        override foo(): void {

        }
    }

    func: H = new H() {

    }
}
