#  No dependencies on TypeScript code are currently allowed

Rule ``arkts-no-ts-deps``

**Severity: error**

Currently, the codebase implemented in the standard TypeScript language must not
depend on ArkTS through importing the ArkTS codebase. Imports in reverse
direction are supported.


## TypeScript


```

    // app.ets
    export class C {
        // ...
    }

    // lib.ts
    import { C } from "app"


```

## ArkTS


```

    // lib1.ets
    export class C {
        // ...
    }

    // lib2.ets
    import { C } from "lib1"

```


