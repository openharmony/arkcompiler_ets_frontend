#  ``Function.bind`` is not supported

Rule ``arkts-no-func-bind``

**Severity: warning**

ArkTS does not allow using standard library function ``Function.bind``.
This API is needed in the standard library to explicitly set ``this``
parameter for the called function.
In ArkTS the semantics of ``this`` is restricted to the conventional OOP
style, and the usage of ``this`` in stand-alone functions is prohibited.
Thus this function is excessive.


## TypeScript


```

    const person = {
        firstName: "aa",

        fullName: function(): string {
            return this.firstName
        }
    }

    const person1 = {
        firstName: "Mary"
    }

    // This will log "Mary":
    const boundFullName = person.fullName.bind(person1)
    console.log(boundFullName())

```

## ArkTS


```

    class Person {
        firstName : string

        constructor(firstName : string) {
            this.firstName = firstName
        }
        fullName() : string {
            return this.firstName
        }
    }

    let person = new Person("")
    let person1 = new Person("Mary")

    // This will log "Mary":
    console.log(person1.fullName())

```

## See also

- Recipe 093:  Using ``this`` inside stand-alone functions is not supported (``arkts-no-standalone-this``)


