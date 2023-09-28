#  ``Symbol()`` API is not supported

Rule ``arkts-no-symbol``

**Severity: error**

TypeScript has ``Symbol()`` API, which can be used among other things to generate
unique property names at runtime. ArkTS does not support ``Symbol()`` API
because its most popular use cases make no sense in the statically typed
environment. In particular, the object layout is defined at compile time,
and cannot be changed at runtime.

``Symbol.iterator`` and iterable interfaces are not supported either.
Use arrays and library-level containers to iterate over data.


## TypeScript


```

    const sym = Symbol()
    let o = {
       [sym]: "value"
    }

    let obj = {
        data: ['a', 'b', 'c'],
        [Symbol.iterator]() {
            const this_ = this
            let index = 0
            return {
                next() {
                    return {
                        done: index >= this_.data.length,
                        value: 'name_' + this_.data[index++]
                    }
                }
            }
        }
    }

    for (let t of obj) {
        console.log(t)
    }

```

## ArkTS


```

    class SomeClass {
        public someProperty : string = ""
    }
    let o = new SomeClass()

    let arr:string[] = ['a', 'b', 'c']
    for (let t of arr) {
        console.log('name_' + t)
    }

```

## See also

- Recipe 001:  Objects with property names that are not identifiers are not supported (``arkts-identifiers-as-prop-names``)
- Recipe 029:  Indexed access is not supported for fields (``arkts-no-props-by-index``)
- Recipe 059:  ``delete`` operator is not supported (``arkts-no-delete``)
- Recipe 060:  ``typeof`` operator is allowed only in expression contexts (``arkts-no-type-query``)
- Recipe 066:  ``in`` operator is not supported (``arkts-no-in``)
- Recipe 105:  Property-based runtime type checks are not supported (``arkts-no-prop-existence-check``)
- Recipe 144:  Usage of standard library is restricted (``arkts-limited-stdlib``)


