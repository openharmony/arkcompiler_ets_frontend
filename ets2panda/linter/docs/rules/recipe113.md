#  ``enum`` declaration merging is not supported

Rule ``arkts-no-enum-merging``

**Severity: error**

ArkTS does not support merging declarations for ``enum``. Keep the
declaration of each ``enum`` compact in the codebase.


## TypeScript


```

    enum Color {
        RED,
        GREEN
    }
    enum Color {
        YELLOW = 2
    }
    enum Color {
        BLACK = 3,
        BLUE
    }

```

## ArkTS


```

    enum Color {
        RED,
        GREEN,
        YELLOW,
        BLACK,
        BLUE
    }

```


