#  ``in`` operator is not supported

Rule ``arkts-no-in``

**Severity: error**

ArkTS does not support the operator ``in``. However, this operator makes
little sense since the object layout is known at compile time, and cannot
be modified at runtime. Use ``instanceof`` as a workaround if you still need
to check whether certain class members exist.


## TypeScript


```

    class Person {
        name: string = ""
    }
    let p = new Person()

    let b = "name" in p // true

```

## ArkTS


```

    class Person {
        name: string = ""
    }
    let p = new Person()

    let b = p instanceof Person // true, and "name" is guaranteed to be present

```

## See also

- Recipe 001:  Objects with property names that are not identifiers are not supported (``arkts-identifiers-as-prop-names``)
- Recipe 002:  ``Symbol()`` API is not supported (``arkts-no-symbol``)
- Recipe 029:  Indexed access is not supported for fields (``arkts-no-props-by-index``)
- Recipe 059:  ``delete`` operator is not supported (``arkts-no-delete``)
- Recipe 060:  ``typeof`` operator is allowed only in expression contexts (``arkts-no-type-query``)
- Recipe 144:  Usage of standard library is restricted (``arkts-limited-stdlib``)


