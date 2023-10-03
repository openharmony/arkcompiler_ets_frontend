#  ``typeof`` operator is allowed only in expression contexts

Rule ``arkts-no-type-query``

**Severity: error**

ArkTS supports ``typeof`` operator only in the expression context. Using
``typeof`` to specify type notations is not supported.


## TypeScript


```

    let n1 = 42
    let s1 = "foo"
    console.log(typeof n1) // "number"
    console.log(typeof s1) // "string"
    let n2: typeof n1
    let s2: typeof s1

```

## ArkTS


```

    let n1 = 42
    let s1 = "foo"
    console.log(typeof n1) // "number"
    console.log(typeof s1) // "string"
    let n2: number
    let s2: string

```

## See also

- Recipe 001:  Objects with property names that are not identifiers are not supported (``arkts-identifiers-as-prop-names``)
- Recipe 002:  ``Symbol()`` API is not supported (``arkts-no-symbol``)
- Recipe 029:  Indexed access is not supported for fields (``arkts-no-props-by-index``)
- Recipe 059:  ``delete`` operator is not supported (``arkts-no-delete``)
- Recipe 066:  ``in`` operator is not supported (``arkts-no-in``)
- Recipe 144:  Usage of standard library is restricted (``arkts-limited-stdlib``)


