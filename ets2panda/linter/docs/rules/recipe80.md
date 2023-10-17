#  ``for .. in`` is not supported

Rule ``arkts-no-for-in``

**Severity: error**

ArkTS does not support the iteration over object contents by the
``for .. in`` loop. For objects, iteration over properties at runtime is
considered redundant because object layout is known at compile time, and
cannot change at runtime. For arrays, iterate with the regular ``for`` loop.


## TypeScript


```

    let a: number[] = [1.0, 2.0, 3.0]
    for (let i in a) {
        console.log(a[i])
    }

```

## ArkTS


```

    let a: number[] = [1.0, 2.0, 3.0]
    for (let i = 0; i < a.length; ++i) {
        console.log(a[i])
    }

```

## See also

- Recipe 082:  ``for-of`` is supported only for arrays, strings, sets, maps and classes derived from them (``arkts-for-of-str-arr``)


