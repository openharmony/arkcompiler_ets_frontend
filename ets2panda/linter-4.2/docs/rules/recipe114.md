#  Namespaces cannot be used as objects

Rule ``arkts-no-ns-as-obj``

**Severity: error**

ArkTS does not support the usage of namespaces as objects.
Classes or modules can be interpreted as analogues of namespaces.


## TypeScript


```

    namespace MyNamespace {
        export let x: number
    }

    let m = MyNamespace
    m.x = 2

```

## ArkTS


```

    namespace MyNamespace {
        export let x: number
    }

    MyNamespace.x = 2

```


