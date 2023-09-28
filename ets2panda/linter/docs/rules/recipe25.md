#  Declaring fields in ``constructor`` is not supported

Rule ``arkts-no-ctor-prop-decls``

**Severity: error**

ArkTS does not support declaring class fields in the ``constructor``.
Declare  class fields inside the ``class`` declaration instead.


## TypeScript


```

    class Person {
        constructor(
            protected ssn: string,
            private firstName: string,
            private lastName: string
        ) {
            this.ssn = ssn
            this.firstName = firstName
            this.lastName = lastName
        }

        getFullName(): string {
            return this.firstName + " " + this.lastName
        }
    }

```

## ArkTS


```

    class Person {
        protected ssn: string
        private firstName: string
        private lastName: string

        constructor(ssn: string, firstName: string, lastName: string) {
            this.ssn = ssn
            this.firstName = firstName
            this.lastName = lastName
        }

        getFullName(): string {
            return this.firstName + " " + this.lastName
        }
    }

```


