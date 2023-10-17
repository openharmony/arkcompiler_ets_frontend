#  Destructuring variable declarations are not supported

Rule ``arkts-no-destruct-decls``

**Severity: error**

ArkTS does not support destructuring variable declarations. This is a dynamic
feature relying on structural compatibility. In addition, names in destructuring
declarations must be equal to properties within destructured classes.


## TypeScript


```

    class Point {
        x: number = 0.0
        y: number = 0.0
    }

    function returnZeroPoint(): Point {
        return new Point()
    }

    let {x, y} = returnZeroPoint()

```

## ArkTS


```

    class Point {
        x: number = 0.0
        y: number = 0.0
    }

    function returnZeroPoint(): Point {
        return new Point()
    }

    // Create an intermediate object and work with it field by field
    // without name restrictions:
    let zp = returnZeroPoint()
    let x = zp.x
    let y = zp.y

```


