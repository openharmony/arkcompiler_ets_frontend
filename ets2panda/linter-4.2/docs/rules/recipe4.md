#  Use unique names for types and namespaces.

Rule ``arkts-unique-names``

**Severity: error**

Names for all types (classes, interfaces, enums) and namespaces must be unique
and distinct from other names, e.g., variable names and function names.


## TypeScript


```

    let X: string
    type X = number[] // Type alias with the same name as the variable

```

## ArkTS


```

    let X: string
    type T = number[] // X is not allowed here to avoid name collisions

```


