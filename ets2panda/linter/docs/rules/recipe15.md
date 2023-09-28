#  Use ``class`` instead of a type with constructor signature

Rule ``arkts-no-ctor-signatures-type``

**Severity: error**

ArkTS does not support constructor signatures in object types. Use classes
instead.


## TypeScript


```

    class SomeObject {}

    type SomeConstructor = {
        new (s: string): SomeObject
    }

    function fn(ctor: SomeConstructor) {
        return new ctor("hello")
    }

```

## ArkTS


```

    class SomeObject {
        public f: string
        constructor (s: string) {
            this.f = s
        }
    }

    function fn(s: string): SomeObject {
        return new SomeObject(s)
    }

```

## See also

- Recipe 014:  Use ``class`` instead of a type with call signature (``arkts-no-call-signatures``)


