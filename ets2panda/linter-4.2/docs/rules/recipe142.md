#  ``as const`` assertions are not supported

Rule ``arkts-no-as-const``

**Severity: error**

ArkTS does not support ``as const`` assertions because in the standard TypeScript
``as const`` annotates literals with corresponding literal types, and ArkTS
does not support literal types.


## TypeScript


```

    // Type 'hello':
    let x = "hello" as const

    // Type 'readonly [10, 20]':
    let y = [10, 20] as const

    // Type '{ readonly text: "hello" }':
    let z = { text: "hello" } as const

```

## ArkTS


```

    // Type 'string':
    let x : string = "hello"

    // Type 'number[]':
    let y : number[] = [10, 20]

    class Label {
        text : string = ""
    }

    // Type 'Label':
    let z : Label = {
        text: "hello"
    }

```


