#  Use ``let`` instead of ``var``

Rule ``arkts-no-var``

**Severity: error**

ArkTS does not support ``var``. Use ``let`` instead.


## TypeScript


```

    function f(shouldInitialize: boolean) {
        if (shouldInitialize) {
           var x = 10
        }
        return x
    }

    console.log(f(true))  // 10
    console.log(f(false)) // undefined

    let upper_let = 0
    {
        var scoped_var = 0
        let scoped_let = 0
        upper_let = 5
    }
    scoped_var = 5 // Visible
    scoped_let = 5 // Compile-time error

```

## ArkTS


```

    function f(shouldInitialize: boolean): Object {
        let x: Object = new Object()
        if (shouldInitialize) {
            x = 10
        }
        return x
    }

    console.log(f(true))  // 10
    console.log(f(false)) // {}

    let upper_let = 0
    let scoped_var = 0
    {
        let scoped_let = 0
        upper_let = 5
    }
    scoped_var = 5
    scoped_let = 5 // Compile-time error

```


