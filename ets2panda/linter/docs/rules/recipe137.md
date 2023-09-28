#  ``globalThis`` is not supported

Rule ``arkts-no-globalthis``

**Severity: error**

ArkTS does not support both global scope and ``globalThis`` because untyped
objects with dynamically changed layout are not supported.


## TypeScript


```

    // in a global file:
    var abc = 100

    // Refers to 'abc' from above.
    globalThis.abc = 200

```

## ArkTS


```

    // file1
    export let abc : number = 0

    // file2
    import * as M from "file1"

    M.abc = 200

```

## See also

- Recipe 139:  Declaring properties on functions is not supported (``arkts-no-func-props``)
- Recipe 144:  Usage of standard library is restricted (``arkts-limited-stdlib``)


