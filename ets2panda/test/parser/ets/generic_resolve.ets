class Foo<T> {
    private constructor() {
    }

    then<U>(onFulfilled: () => U): Foo<U> {
        let promise = new Foo<U>();
        let fn: () => void = (): void => {
            let res: U = onFulfilled();
            promise.resolve(res);
        }
        return promise;
    }

    private native resolve(value: T): void;
}
