export declare class Something { beep(): number }

export declare class SomethingFactory {
    private constructor();

    public static getInstance(): SomethingFactory;

    public create1<T extends Something>(arg: { new(): T }): T;
    public create2<T extends Something>(arg: { o: { new(): T } }): T;
    public create3<T extends Something>(arg: () => { new(): T }): T;
    public create4<T extends Something>(arg: Function): T;
}

export declare class SomethingBar extends Something { }

export declare class Bar<T extends Something> {
    constructor(arg: { new(): T });
}
