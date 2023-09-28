#  Use ``class`` instead of a type with call signature

Rule ``arkts-no-call-signatures``

**Severity: error**

ArkTS does not support call signatures in object types. Use classes instead.


## TypeScript


```

    type DescribableFunction = {
        description: string
        (someArg: number): string // call signature
    }

    function doSomething(fn: DescribableFunction): void {
        console.log(fn.description + " returned " + fn(6))
    }

```

## ArkTS


```

    class DescribableFunction {
        description: string
        public invoke(someArg: number): string {
            return someArg.toString()
        }
        constructor() {
            this.description = "desc"
        }
    }

    function doSomething(fn: DescribableFunction): void {
        console.log(fn.description + " returned " + fn.invoke(6))
    }

    doSomething(new DescribableFunction())

```

## See also

- Recipe 015:  Use ``class`` instead of a type with constructor signature (``arkts-no-ctor-signatures-type``)


