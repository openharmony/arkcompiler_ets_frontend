#  Use explicit types instead of ``any``, ``unknown``

Rule ``arkts-no-any-unknown``

**Severity: error**

ArkTS does not support the types ``any`` and ``unknown``. Specify
types explicitly.


## TypeScript


```

    let value1 : any
    value1 = true
    value1 = 42

    let value2 : unknown
    value2 = true
    value2 = 42

```

## ArkTS


```

    let value_b: boolean = true // OR: let value_b = true
    let value_n: number = 42 // OR: let value_n = 42
    let value_o1: Object = true
    let value_o2: Object = 42

```

## See also

- Recipe 013:  Use ``Object[]`` instead of tuples (``arkts-no-tuples``)
- Recipe 145:  Strict type checking is enforced (``arkts-strict-typing``)


