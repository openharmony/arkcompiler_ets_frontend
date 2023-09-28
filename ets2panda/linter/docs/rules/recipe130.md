#  Universal module definitions (UMD) are not supported

Rule ``arkts-no-umd``

**Severity: error**

ArkTS does not support universal module definitions (UMD) because in the
language there is no concept of "script" (as opposed to "module").
Besides, in ArkTS import is a compile-time, not a runtime feature.
Use ordinary syntax for ``export`` and ``import`` instead.


## TypeScript


```

    // math-lib.d.ts
    export const isPrime(x: number): boolean
    export as namespace mathLib

    // in script
    mathLib.isPrime(2)

```

## ArkTS


```

    // math-lib.d.ts
    namespace mathLib {
        export isPrime(x: number): boolean
    }

    // in program
    import { mathLib } from "math-lib"
    mathLib.isPrime(2)

```

## See also

- Recipe 129:  Wildcards in module names are not supported (``arkts-no-module-wildcards``)


