#  ``import`` statements after other statements are not allowed

Rule ``arkts-no-misplaced-imports``

**Severity: error**

In ArkTS, all ``import`` statements should go before all other statements
in the program.


## TypeScript


```

    class C {
        s: string = ""
        n: number = 0
    }

    import foo from "module1"

```

## ArkTS


```

    import foo from "module1"

    class C {
        s: string = ""
        n: number = 0
    }

```


