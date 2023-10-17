    // Explicitly exported class:
    export class Class1 {
        // ...
    }

    // Declared class later exported through export type ...
    class Class2 {
        // ...
    }

    // This is not supported:
    export type { Class2 }