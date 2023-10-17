#  Unary operators ``+``, ``-`` and ``~`` work only on numbers

Rule ``arkts-no-polymorphic-unops``

**Severity: error**

ArkTS allows unary operators to work on numeric types only. A compile-time
error occurs if these operators are applied to a non-numeric type. Unlike in
TypeScript, implicit casting of strings in this context is not supported and must
be done explicitly.


## TypeScript


```

    let a = +5        // 5 as number
    let b = +"5"      // 5 as number
    let c = -5        // -5 as number
    let d = -"5"      // -5 as number
    let e = ~5        // -6 as number
    let f = ~"5"      // -6 as number
    let g = +"string" // NaN as number

    function returnTen(): string {
        return "-10"
    }

    function returnString(): string {
        return "string"
    }

    let x = +returnTen()    // -10 as number
    let y = +returnString() // NaN

```

## ArkTS


```

    let a = +5        // 5 as number
    let b = +"5"      // Compile-time error
    let c = -5        // -5 as number
    let d = -"5"      // Compile-time error
    let e = ~5        // -6 as number
    let f = ~"5"      // Compile-time error
    let g = +"string" // Compile-time error

    function returnTen(): string {
        return "-10"
    }

    function returnString(): string {
        return "string"
    }

    let x = +returnTen()    // Compile-time error
    let y = +returnString() // Compile-time error

```


