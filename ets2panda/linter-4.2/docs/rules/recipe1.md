#  Objects with property names that are not identifiers are not supported

Rule ``arkts-identifiers-as-prop-names``

**Severity: error**

ArkTS does not support Objects with name properties that are numbers or
strings. Use classes to access data by property names. Use arrays to access
data by numeric indices.


## TypeScript


```

    var x = {"name": 1, 2: 3}

    console.log(x["name"])
    console.log(x[2])

```

## ArkTS


```

    class X {
        public name: number = 0
    }
    let x:X = {name: 1}
    console.log(x.name)

    let y = [1, 2, 3]
    console.log(y[2])

    // If you still need a container to store keys of different types,
    // use Map<Object, some_type>:
    let z = new Map<Object, number>()
    z.set("name", 1)
    z.set(2, 2)
    console.log(z.get("name"))
    console.log(z.get(2))

```

## See also

- Recipe 002:  ``Symbol()`` API is not supported (``arkts-no-symbol``)
- Recipe 029:  Indexed access is not supported for fields (``arkts-no-props-by-index``)
- Recipe 059:  ``delete`` operator is not supported (``arkts-no-delete``)
- Recipe 060:  ``typeof`` operator is allowed only in expression contexts (``arkts-no-type-query``)
- Recipe 066:  ``in`` operator is not supported (``arkts-no-in``)
- Recipe 144:  Usage of standard library is restricted (``arkts-limited-stdlib``)


