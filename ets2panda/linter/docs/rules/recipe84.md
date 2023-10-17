#  ``with`` statement is not supported

Rule ``arkts-no-with``

**Severity: error**

ArkTS does not support the ``with`` statement. Use other language idioms
(including fully qualified names of functions) to achieve that same behavior.


## TypeScript


```

    with (Math) { // Compile-time error, but JavaScript code still emitted
        let r: number = 42
        console.log("Area: ", PI * r * r)
    }

```

## ArkTS


```

    let r: number = 42
    console.log("Area: ", Math.PI * r * r)

```


