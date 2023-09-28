#  Indexed signatures are not supported

Rule ``arkts-no-indexed-signatures``

**Severity: error**

ArkTS does not allow indexed signatures. Use arrays instead.


## TypeScript


```

    // Interface with an indexed signature:
    interface StringArray {
        [index: number]: string
    }

    function getStringArray() : StringArray {
        return ["a", "b", "c"]
    }

    const myArray: StringArray = getStringArray()
    const secondItem = myArray[1]

```

## ArkTS


```

    class X {
        public f: string[] = []
    }

    let myArray: X = new X()
    const secondItem = myArray.f[1]

```


