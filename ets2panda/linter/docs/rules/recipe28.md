#  Indexed access types are not supported

Rule ``arkts-no-aliases-by-index``

**Severity: error**

ArkTS does not support indexed access types. Use the type name instead.


## TypeScript


```

    type Point = {x: number, y: number}
    type N = Point["x"] // is equal to number

```

## ArkTS


```

    class Point {x: number = 0; y: number = 0}
    type N = number

```


