#  ``instanceof`` operator is partially supported

Rule ``arkts-instanceof-ref-types``

**Severity: error**

In TypeScript, the left-hand side of an ``instanceof`` expression must be of the type
``any``, an object type or a type parameter; the result is ``false`` otherwise.
In ArkTS, the left-hand side expression may be of any reference type;
a compile-time error occurs otherwise. In addition, the left operand in ArkTS
cannot be a type.


## TypeScript


```

    class X {
        // ...
    }

    let a = (new X()) instanceof Object // true
    let b = (new X()) instanceof X      // true

    let c = X instanceof Object // true, left operand is a type
    let d = X instanceof X      // false, left operand is a type

```

## ArkTS


```

    class X {
        // ...
    }

    let a = (new X()) instanceof Object // true
    let b = (new X()) instanceof X      // true

    let c = X instanceof Object // Compile-time error, left operand is a type
    let d = X instanceof X      // Compile-time error, left operand is a type

```


