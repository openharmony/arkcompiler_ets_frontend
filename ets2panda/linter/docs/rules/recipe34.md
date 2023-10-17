#  Type inference in case of generic function calls is limited

Rule ``arkts-no-inferred-generic-params``

**Severity: error**

ArkTS allows to omit generic type parameters if it is possible to infer
the concrete types from the parameters passed to the function. A compile-time
error occurs otherwise. In particular, inference of generic type parameters
based only on function return types is prohibited.


## TypeScript


```

    function choose<T>(x: T, y: T): T {
        return Math.random() < 0.5 ? x : y
    }

    let x = choose(10, 20)   // OK, choose<number>(...) is inferred
    let y = choose("10", 20) // Compile-time error

    function greet<T>(): T {
        return "Hello" as T
    }
    let z = greet() // Type of T is inferred as "unknown"

```

## ArkTS


```

    function choose<T>(x: T, y: T): T {
        return Math.random() < 0.5 ? x : y
    }

    let x = choose(10, 20)   // OK, choose<number>(...) is inferred
    let y = choose("10", 20) // Compile-time error

    function greet<T>(): T {
        return "Hello" as T
    }
    let z = greet<string>()

```


