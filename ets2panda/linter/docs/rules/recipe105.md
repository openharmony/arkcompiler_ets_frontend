#  Property-based runtime type checks are not supported

Rule ``arkts-no-prop-existence-check``

**Severity: error**

ArkTS requires that object layout is determined at compile time, and cannot
be changed at runtime. Therefore, property-based runtime checks are not
supported.
If you need to do a type cast, use the operator ``as`` with desired properties
and methods.
If some property does not exist, then an attempt to refer to it causes a
compile-time error.


## TypeScript


```

    class A {
        foo() {}
        bar() {}
    }

    function getSomeObject() {
        return new A()
    }

    let obj: any = getSomeObject()
    if (obj && obj.foo && obj.bar) {
        console.log("Yes")  // prints "Yes" in this example
    } else {
        console.log("No")
    }

```

## ArkTS


```

    class A {
        foo(): void {}
        bar(): void {}
    }

    function getSomeObject(): A {
        return new A()
    }

    function main(): void {
        let tmp: Object = getSomeObject()
        let obj: A = tmp as A
        obj.foo()       // OK
        obj.bar()       // OK
        obj.some_foo()  // Compile-time error: Method some_foo does not
                        // exist on this type
    }

```

## See also

- Recipe 001:  Objects with property names that are not identifiers are not supported (``arkts-identifiers-as-prop-names``)
- Recipe 002:  ``Symbol()`` API is not supported (``arkts-no-symbol``)
- Recipe 029:  Indexed access is not supported for fields (``arkts-no-props-by-index``)
- Recipe 059:  ``delete`` operator is not supported (``arkts-no-delete``)
- Recipe 060:  ``typeof`` operator is allowed only in expression contexts (``arkts-no-type-query``)
- Recipe 066:  ``in`` operator is not supported (``arkts-no-in``)
- Recipe 144:  Usage of standard library is restricted (``arkts-limited-stdlib``)


