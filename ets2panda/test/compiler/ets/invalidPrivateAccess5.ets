class Outer {
    class Base {
        private a(): void {};
    }

    class Derived extends Base {
        foo(): void {
            let base: Base = new Base();
            base.a();
            this.a();
        }
    }
}
