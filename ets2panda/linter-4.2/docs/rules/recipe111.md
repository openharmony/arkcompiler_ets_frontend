#  Enumeration members can be initialized only with compile time expressions of the same type

Rule ``arkts-no-enum-mixed-types``

**Severity: error**

ArkTS does not support initializing members of enumerations with expressions
that are evaluated during program runtime. Besides, all explicitly set
initializers must be of the same type.


## TypeScript


```

    enum E1 {
        A = 0xa,
        B = 0xb,
        C = Math.random(),
        D = 0xd,
        E // 0xe inferred
    }

    enum E2 {
        A = 0xa,
        B = "0xb",
        C = 0xc,
        D = "0xd"
    }

```

## ArkTS


```

    enum E1 {
        A = 0xa,
        B = 0xb,
        C = 0xc,
        D = 0xd,
        E // 0xe inferred
    }

    enum E2 {
        A = "0xa",
        B = "0xb",
        C = "0xc",
        D = "0xd"
    }

```


