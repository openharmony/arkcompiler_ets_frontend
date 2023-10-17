#  Construct signatures are not supported in interfaces

Rule ``arkts-no-ctor-signatures-iface``

**Severity: error**

ArkTS does not support construct signatures. Use methods instead.


## TypeScript


```

    interface I {
        new (s: string): I
    }

    function fn(i: I) {
        return new i("hello")
    }

```

## ArkTS


```

    interface I {
        create(s: string): I
    }

    function fn(i: I) {
        return i.create("hello")
    }

```

## See also

- Recipe 015:  Use ``class`` instead of a type with constructor signature (``arkts-no-ctor-signatures-type``)


