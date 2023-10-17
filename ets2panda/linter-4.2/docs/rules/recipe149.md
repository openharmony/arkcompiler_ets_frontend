#  Classes cannot be used as objects

Rule ``arkts-no-classes-as-obj``

**Severity: error**

ArkTS does not support using classes as objects (assigning them to variables,
etc.) because in ArkTS, a ``class`` declaration introduces a new type,
not a value.


## TypeScript


```

    class C {
        s: string = ""
        n: number = 0
    }

    let c = C

```


