#  Private '#' identifiers are not supported

Rule ``arkts-no-private-identifiers``

**Severity: error**

ArkTS does not use private identifiers starting with the symbol ``#``. Use
the keyword  ``private`` instead.


## TypeScript


```

    /*
     * Such notation for private fields is not supported in ArkTS:
    class C {
        #foo: number = 42
    }
    */

```

## ArkTS


```

    class C {
        private foo: number = 42
    }

```


