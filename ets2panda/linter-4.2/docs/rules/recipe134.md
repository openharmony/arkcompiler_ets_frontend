#  Definite assignment assertions are not supported

Rule ``arkts-no-definite-assignment``

**Severity: warning**

ArkTS does not support definite assignment assertions ``let v!: T`` because
they are considered an excessive compiler hint.
Use declaration with initialization instead.


## TypeScript


```

    let x!: number // Hint: x will be initialized before usage

    initialize()

    function initialize() {
        x = 10
    }

    console.log("x = " + x)

```

## ArkTS


```

    function initialize() : number {
        return 10
    }

    let x: number = initialize()

    console.log("x = " + x)

```


