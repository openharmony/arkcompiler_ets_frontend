#  Special ``export type`` declarations are not supported

Rule ``arkts-no-special-exports``

**Severity: error**

ArkTS does not have a special notation for exporting types through
``export type ...``. Use ordinary export instead.


## TypeScript


```

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

```

## ArkTS


```

    // Explicitly exported class:
    export class Class1 {
        // ...
    }

    // Explicitly exported class:
    export class Class2 {
        // ...
    }

```


