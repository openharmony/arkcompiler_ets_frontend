#  Conditional types are not supported

Rule ``arkts-no-conditional-types``

**Severity: error**

ArkTS does not support conditional type aliases. Introduce a new type with
constraints explicitly, or rewrite logic using ``Object``. The keyword
``infer`` is not supported.


## TypeScript


```

    type X<T> = T extends number ? T : never

    type Y<T> = T extends Array<infer Item> ? Item : never

```

## ArkTS


```

    // Provide explicit constraints within type alias
    type X1<T extends number> = T

    // Rewrite with Object. Less type control, need more type checks for safety
    type X2<T> = Object

    // Item has to be used as a generic parameter and need to be properly
    // instantiated
    type YI<Item, T extends Array<Item>> = Item

```


