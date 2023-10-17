#  Nested functions are not supported

Rule ``arkts-no-nested-funcs``

**Severity: error**

ArkTS does not support nested functions. Use lambdas instead.


## TypeScript


```

    function addNum(a: number, b: number): void {

        // nested function:
        function logToConsole(message: String): void {
            console.log(message)
        }

        let result = a + b

        // Invoking the nested function:
        logToConsole("result is " + result)
    }

```

## ArkTS


```

    function addNum(a: number, b: number): void {
        // Use lambda instead of a nested function:
        let logToConsole: (message: string) => void = (message: string): void => {
            console.log(message)
        }

        let result = a + b

        logToConsole("result is " + result)
    }

```


