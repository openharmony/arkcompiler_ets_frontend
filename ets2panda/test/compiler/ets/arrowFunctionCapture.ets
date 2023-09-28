class A {
    foo(): void{}
    bar(a0: int): void{
        let func: (a1: int) => void = (a1: int): void => {
            a0;
            a1;
            this.foo();
        }

        func(2);
    }
}
