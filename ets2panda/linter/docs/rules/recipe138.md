#  Some of utility types are not supported

Rule ``arkts-no-utility-types``

**Severity: error**

Currently ArkTS does not support utility types from TypeScript extensions to the
standard library, except following: ``Partial``, ``Required``, ``Readonly``, ``Record``.

For the type *Record<K, V>*, the type of an indexing expression *rec[index]* is
of the type *V | undefined*.


## TypeScript


```

    type Person = {
        name: string
        age: number
        location: string
    }

    type QuantumPerson = Omit<Person, "location">

    let persons : Record<string, Person> = {
        "Alice": {
            name: "Alice",
            age: 32,
            location: "Shanghai"
        },
        "Bob": {
            name: "Bob",
            age: 48,
            location: "New York"
        }
    }
    console.log(persons["Bob"].age)
    console.log(persons["Rob"].age) // Runtime exception

```

## ArkTS


```

    class Person {
        name: string = ""
        age: number = 0
        location: string = ""
    }

    class QuantumPerson {
        name: string = ""
        age: number = 0
    }

    type OptionalPerson = Person | undefined
    let persons : Record<string, OptionalPerson> = {
    // Or:
    // let persons : Record<string, Person | undefined> = {
        "Alice": {
            name: "Alice",
            age: 32,
            location: "Shanghai"
        },
        "Bob": {
            name: "Bob",
            age: 48,
            location: "New York"
        }
    }
    console.log(persons["Bob"]!.age)
    if (persons["Rob"]) { // Explicit value check, no runtime exception
        console.log(persons["Rob"].age)
    }

```


