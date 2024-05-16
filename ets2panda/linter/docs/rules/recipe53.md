#  Only ``as T`` syntax is supported for type casts

Rule ``arkts-as-casts``

**Severity: error**

ArkTS supports the keyword ``as`` as the only syntax for type casts.
Incorrect cast causes a compile-time error or runtime ``ClassCastError``.
``<type>`` syntax for type casts is not supported.

Use the expression ``new ...`` instead of ``as`` if a **primitive** type
(e.g., a ``number`` or a ``boolean``) must be cast to the reference type.


## TypeScript


```

    class Shape {}
    class Circle extends Shape {x: number = 5}
    class Square extends Shape {y: string = "a"}

    function createShape(): Shape {
        return new Circle()
    }

    let c1 = <Circle> createShape()

    let c2 = createShape() as Circle

    // No report is provided during compilation
    // nor during runtime if cast is wrong:
    let c3 = createShape() as Square
    console.log(c3.y) // undefined

    // Important corner case for casting primitives to the boxed counterparts:
    // The left operand is not properly boxed here in in runtime
    // because "as" has no runtime effect in TypeScript
    let e1 = (5.0 as Number) instanceof Number // false

    // Number object is created and instanceof works as expected:
    let e2 = (new Number(5.0)) instanceof Number // true

```

## ArkTS


```

    class Shape {}
    class Circle extends Shape {x: number = 5}
    class Square extends Shape {y: string = "a"}

    function createShape(): Shape {
        return new Circle()
    }

    let c2 = createShape() as Circle

    // ClassCastError during runtime is thrown:
    let c3 = createShape() as Square

    // Number object is created and instanceof works as expected:
    let e2 = (new Number(5.0)) instanceof Number // true

```


