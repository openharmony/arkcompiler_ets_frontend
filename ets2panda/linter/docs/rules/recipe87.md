#  ``throw`` statements cannot accept values of arbitrary types

Rule ``arkts-limited-throw``

**Severity: error**

ArkTS supports throwing only objects of the class ``Error`` or any
derived class. Throwing an arbitrary type (i.e., a ``number`` or ``string``)
is prohibited.


## TypeScript


```

    throw 4
    throw ""
    throw new Error()

```

## ArkTS


```

    throw new Error()

```


