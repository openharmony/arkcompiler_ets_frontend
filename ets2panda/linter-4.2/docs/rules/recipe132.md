#  ``new.target`` is not supported

Rule ``arkts-no-new-target``

**Severity: error**

ArkTS does not support ``new.target`` because there is no concept of runtime
prototype inheritance in the language. This feature is considered not applicable
to static typing.


## TypeScript


```

    class CustomError extends Error {
        constructor(message?: string) {
            // 'Error' breaks prototype chain here:
            super(message)

            // Restore prototype chain:
            Object.setPrototypeOf(this, new.target.prototype)
        }
    }

```

## ArkTS


```

    class CustomError extends Error {
        constructor(message?: string) {
            // Call parent's constructor, inheritance chain is static and
            // cannot be modified in runtime
            super(message)
            console.log(this instanceof Error) // true
        }
    }
    let ce = new CustomError()

```

## See also

- Recipe 136:  Prototype assignment is not supported (``arkts-no-prototype-assignment``)


