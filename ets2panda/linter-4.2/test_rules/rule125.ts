    // module1
    export class Class1 {
        // ...
    }
    export class Class2 {
        // ...
    }

    // module2
    export * as utilities from "module1"

    // consumer module
    import { utilities } from "module2"