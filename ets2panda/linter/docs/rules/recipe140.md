#  ``Function.apply``, ``Function.bind``, ``Function.call`` are not supported

Rule ``arkts-no-func-apply-bind-call``

**Severity: error**

ArkTS does not allow using standard library functions ``Function.apply``,
``Function.bind`` and ``Function.call``. These APIs are needed in the standard
library to explicitly set ``this`` parameter for the called function.
In ArkTS the semantics of ``this`` is restricted to the conventional OOP
style, and the usage of ``this`` in stand-alone functions is prohibited.
Thus these functions are excessive.


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
    console.log(person.fullName.apply(person1))

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


