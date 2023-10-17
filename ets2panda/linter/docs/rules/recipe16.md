#  Only one static block is supported

Rule ``arkts-no-multiple-static-blocks``

**Severity: error**

ArkTS does not allow having several static blocks for class initialization.
Combine static block statements into one static block.


## TypeScript


```

    class C {
        static s: string

        static {
            C.s = "aa"
        }
        static {
            C.s = C.s + "bb"
        }
    }

```

## ArkTS


```


    class C {
        static s: string

        static {
            C.s = "aa"
            C.s = C.s + "bb"
        }
    }


```


