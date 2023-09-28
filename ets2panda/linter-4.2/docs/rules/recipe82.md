#  ``for-of`` is supported only for arrays, strings, sets, maps and classes derived from them

Rule ``arkts-for-of-str-arr``

**Severity: error**

|LANG| supports the iteration over arrays, strings, sets, maps and classes
derived from them by the ``for .. of`` loop, but does not support the
iteration of objects content. All typed arrays from the standard
library (for example, ``Int32Array``) are also supported.

## TypeScript


```

    class A {
        prop1: number;
        prop2: number;
    }
    let a = new A()
    for (let prop of a) {
        console.log(prop)
    }

```

## ArkTS


```

    let a = new Set<number>([1, 2, 3])
    for (let n of a) {
        console.log(n)
    }

```

## See also

- Recipe 080:  ``for .. in`` is not supported (``arkts-no-for-in``)


