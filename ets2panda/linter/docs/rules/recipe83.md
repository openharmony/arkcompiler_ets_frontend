#  Mapped type expression is not supported

Rule ``arkts-no-mapped-types``

**Severity: error**

ArkTS does not support mapped types. Use other language idioms and regular
classes to achieve that same behavior.


## TypeScript


```

    type OptionsFlags<Type> = {
        [Property in keyof Type]: boolean
    }

```

## ArkTS


```

    class C {
        n: number = 0
        s: string = ""
    }

    class CFlags {
        n: boolean = false
        s: boolean = false
    }

```

