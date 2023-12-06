#  Indexed access is not supported for fields

Rule ``arkts-no-props-by-index``

**Severity: error**

ArkTS does not support dynamic field declaration and access. Declare all
object fields immediately in the class. Access only those class fields
that are either declared in the class, or accessible via inheritance. Accessing
any other fields is prohibited, and causes compile-time errors.

To access a field, use ``obj.field`` syntax, indexed access (``obj["field"]``)
is not supported. An exception are: 

- All typed arrays from the standard library (for example, ``Int32Array``), which
support access to their elements through ``container[index]`` syntax.
- Tuples.
- Records.
- Enums.


## TypeScript


```

    class Point {
        x: number = 0
        y: number = 0
    }
    let p: Point = {x: 1, y: 2}
    console.log(p["x"])

    class Person {
        name: string = ""
        age: number = 0; // semicolon is required here
        [key: string]: string | number
    }

    let person: Person = {
        name: "John",
        age: 30,
        email: "***@example.com",
        phoneNumber: "18*********",
    }

```

## ArkTS


```

    class Point {
        x: number = 0
        y: number = 0
    }
    let p: Point = {x: 1, y: 2}
    console.log(p.x)

    class Person {
        name: string
        age: number
        email: string
        phoneNumber: string

        constructor(name: string, age: number, email: string,
                    phoneNumber: string) {
            this.name = name
            this.age = age
            this.email = email
            this.phoneNumber = phoneNumber
        }
    }

    let person = new Person("John", 30, "***@example.com", "18*********")
    console.log(person["name"])         // Compile-time error
    console.log(person.unknownProperty) // Compile-time error

    let arr = new Int32Array(1)
    console.log(arr[0])

```


