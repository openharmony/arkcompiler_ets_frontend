#  Strict type checking is enforced

Rule ``arkts-strict-typing``

**Severity: error**

Type checker in ArkTS is not optional, the code must be explicitly and
correctly types to be compiled and run. When porting from the standard TypeScript,
turn on the following flags: ``noImplicitReturns``, ``strictFunctionTypes``,
``strictNullChecks``, ``strictPropertyInitialization``.


## TypeScript


```

    class C {
        n: number // Compile-time error only with strictPropertyInitialization
        s: string // Compile-time error only with strictPropertyInitialization
    }

    // Compile-time error only with noImplicitReturns
    function foo(s: string): string {
        if (s != "") {
            console.log(s)
            return s
        } else {
            console.log(s)
        }
    }

    let n: number = null // Compile-time error only with strictNullChecks

```

## ArkTS


```

    class C {
        n: number = 0
        s: string = ""
    }

    function foo(s: string): string {
        console.log(s)
        return s
    }

    let n1: number | null = null
    let n2: number = 0

```

## See also

- Recipe 008:  Use explicit types instead of ``any``, ``unknown`` (``arkts-no-any-unknown``)
- Recipe 146:  Switching off type checks with in-place comments is not allowed (``arkts-strict-typing-required``)


