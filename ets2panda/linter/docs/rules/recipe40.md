#  Object literals cannot be used as type declarations

Rule ``arkts-no-obj-literals-as-types``

**Severity: error**

ArkTS does not support the usage of object literals to declare
types in place. Declare classes and interfaces explicitly instead.


## TypeScript


```

    let o: {x: number, y: number} = {
        x: 2,
        y: 3
    }

    type S = Set<{x: number, y: number}>

```

## ArkTS


```

    class O {
        x: number = 0
        y: number = 0
    }

    let o: O = {x: 2, y: 3}

    type S = Set<O>

```

## See also

- Recipe 038:  Object literal must correspond to some explicitly declared class or interface (``arkts-no-untyped-obj-literals``)
- Recipe 043:  Array literals must contain elements of only inferrable types (``arkts-no-noninferrable-arr-literals``)


