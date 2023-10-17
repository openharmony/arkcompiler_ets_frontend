#  Constructor function type is not supported

Rule ``arkts-no-ctor-signatures-funcs``

**Severity: error**

ArkTS does not support the usage of the constructor function type.
Use lambdas instead.


## TypeScript


```

    class Person {
        constructor(
            name: string,
            age: number
        ) {}
    }
    type PersonCtor = new (name: string, age: number) => Person

    function createPerson(Ctor: PersonCtor, name: string, age: number): Person
    {
        return new Ctor(name, age)
    }

    const person = createPerson(Person, 'John', 30)

```

## ArkTS


```

    class Person {
        constructor(
            name: string,
            age: number
        ) {}
    }
    type PersonCtor = (n: string, a: number) => Person

    function createPerson(Ctor: PersonCtor, n: string, a: number): Person {
        return Ctor(n, a)
    }

    let Impersonizer: PersonCtor = (n: string, a: number): Person => {
        return new Person(n, a)
    }

    const person = createPerson(Impersonizer, "John", 30)

```


