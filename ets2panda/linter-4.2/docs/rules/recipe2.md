#  ``Symbol()`` API is not supported

Rule ``arkts-no-symbol``

**Severity: error**

TypeScript has ``Symbol()`` API, which can be used among other things to generate
unique property names at runtime. ArkTS does not support ``Symbol()`` API
because its most popular use cases make no sense in the statically typed
environment. In particular, the object layout is defined at compile time,
and cannot be changed at runtime.

``Symbol.iterator`` and iterable interfaces are supported in ArkTS.


## TypeScript


```

    const sym = Symbol()
    let o = {
       [sym]: "value"
    }

```

## ArkTS


```

    class SomeClass {
        public someProperty : string = ""
    }
    let o = new SomeClass()

```

## See also

- Recipe 001:  Objects with property names that are not identifiers are not supported (``arkts-identifiers-as-prop-names``)
- Recipe 029:  Indexed access is not supported for fields (``arkts-no-props-by-index``)
- Recipe 059:  ``delete`` operator is not supported (``arkts-no-delete``)
- Recipe 060:  ``typeof`` operator is allowed only in expression contexts (``arkts-no-type-query``)
- Recipe 066:  ``in`` operator is not supported (``arkts-no-in``)
- Recipe 144:  Usage of standard library is restricted (``arkts-limited-stdlib``)


