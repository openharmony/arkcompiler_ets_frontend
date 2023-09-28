#  Array literals must contain elements of only inferrable types

Rule ``arkts-no-noninferrable-arr-literals``

**Severity: error**

Basically, ArkTS infers the type of an array literal as a union type of its
contents. However, a compile-time error occurs if there is at least one
element with a non-inferrable type (e.g. untyped object literal).


## TypeScript


```

    let a = [{n: 1, s: "1"}, {n: 2, s : "2"}]

```

## ArkTS


```

    class C {
        n: number = 0
        s: string = ""
    }

    let a1 = [{n: 1, s: "1"} as C, {n: 2, s : "2"} as C] // a1 is of type "C[]"
    let a2: C[] = [{n: 1, s: "1"}, {n: 2, s : "2"}]      // ditto

```

## See also

- Recipe 038:  Object literal must correspond to some explicitly declared class or interface (``arkts-no-untyped-obj-literals``)
- Recipe 040:  Object literals cannot be used as type declarations (``arkts-no-obj-literals-as-types``)


