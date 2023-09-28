class A {
    b: String = "foo";

    a: () => void = (): void => {
        this.b++;
    }
}
