#  ``delete`` operator is not supported

Rule ``arkts-no-delete``

**Severity: error**

ArkTS assumes that object layout is known at compile time and cannot be
changed at runtime. Thus the operation of deleting a property makes no sense.


## TypeScript


```

    class Point {
        x?: number = 0.0
        y?: number = 0.0
    }

    let p = new Point()
    delete p.y

```

## ArkTS


```

    // To mimic the original semantics, you may declare a nullable type
    // and assign null to mark value absence:

    class Point {
        x: number | null = 0
        y: number | null = 0
    }

    let p = new Point()
    p.y = null

```

## See also

- Recipe 001:  Objects with property names that are not identifiers are not supported (``arkts-identifiers-as-prop-names``)
- Recipe 002:  ``Symbol()`` API is not supported (``arkts-no-symbol``)
- Recipe 029:  Indexed access is not supported for fields (``arkts-no-props-by-index``)
- Recipe 060:  ``typeof`` operator is allowed only in expression contexts (``arkts-no-type-query``)
- Recipe 066:  ``in`` operator is not supported (``arkts-no-in``)


