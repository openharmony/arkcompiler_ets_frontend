#  Use inheritance instead of intersection types

Rule ``arkts-no-intersection-types``

**Severity: error**

Currently, ArkTS does not support intersection types. Use inheritance
as a workaround.


## TypeScript


```

    interface Identity {
        id: number
        name: string
    }

    interface Contact {
        email: string
        phoneNumber: string
    }

    type Employee = Identity & Contact

```

## ArkTS


```

    interface Identity {
        id: number
        name: string
    }

    interface Contact {
        email: string
        phoneNumber: string
    }

    interface Employee extends Identity,  Contact {}

```


