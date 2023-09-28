#  Function return type inference is limited

Rule ``arkts-no-implicit-return-types``

**Severity: error**

ArkTS supports type inference for function return types, but this functionality
is currently restricted. In particular, when the expression in the ``return``
statement is a call to a function or method whose return value type is omitted,
a compile-time error occurs. In case of any such error, specify the return type
explicitly.


## TypeScript


```

    // Compile-time error with noImplicitAny
    function f(x: number) {
        if (x <= 0) {
            return x
        }
        return g(x)
    }

    // Compile-time error with noImplicitAny
    function g(x: number) {
        return f(x - 1)
    }

    function doOperation(x: number, y: number) {
        return x + y
    }

    console.log(f(10))
    console.log(doOperation(2, 3))

```

## ArkTS


```

    // Explicit return type is required:
    function f(x: number) : number {
        if (x <= 0) {
            return x
        }
        return g(x)
    }

    // Return type may be omitted, it is inferred from f's explicit type:
    function g(x: number) {
        return f(x - 1)
    }

    // In this case, return type will be inferred
    function doOperation(x: number, y: number) {
        return x + y
    }

    console.log(f(10))
    console.log(doOperation(2, 3))

```


