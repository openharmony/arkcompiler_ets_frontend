#  Interfaces cannot extend classes

Rule ``arkts-extends-only-class``

**Severity: error**

ArkTS does not support interfaces that extend classes. Interfaces can extend
only interfaces.


## TypeScript


```

    class Control {
        state: number = 0
    }

    interface SelectableControl extends Control {
        select(): void
    }

```

## ArkTS


```

    interface Control {
        state: number
    }

    interface SelectableControl extends Control {
        select(): void
    }

```


