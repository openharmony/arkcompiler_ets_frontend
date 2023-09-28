#  Using ``this`` inside stand-alone functions is not supported

Rule ``arkts-no-standalone-this``

**Severity: error**

ArkTS does not support the usage of ``this`` inside stand-alone functions and
inside static methods. ``this`` can be used in instance methods only.


## TypeScript


```

    function foo(i: number) {
        this.count = i // Compile-time error only with noImplicitThis
    }

    class A {
        count: number = 1
        m = foo
    }

    let a = new A()
    console.log(a.count) // prints "1"
    a.m(2)
    console.log(a.count) // prints "2"


```

## ArkTS


```

    class A {
        count: number = 1
        m(i: number): void {
            this.count = i
        }
    }

    function main(): void {
        let a = new A()
        console.log(a.count)  // prints "1"
        a.m(2)
        console.log(a.count)  // prints "2"
    }

```

## See also

- Recipe 140:  ``Function.apply``, ``Function.bind``, ``Function.call`` are not supported (``arkts-no-func-apply-bind-call``)


