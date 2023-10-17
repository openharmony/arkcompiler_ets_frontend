#  Class literals are not supported

Rule ``arkts-no-class-literals``

**Severity: error**

ArkTS does not support class literals. Introduce new named class types
explicitly.


## TypeScript


```

    const Rectangle = class {
        constructor(height: number, width: number) {
            this.height = height
            this.width = width
        }

        height
        width
    }

    const rectangle = new Rectangle(0.0, 0.0)

```

## ArkTS


```

    class Rectangle {
        constructor(height: number, width: number) {
            this.height = height
            this.width = width
        }

        height: number
        width: number
    }

    const rectangle = new Rectangle(0.0, 0.0)

```


