#  Import assertions are not supported

Rule ``arkts-no-import-assertions``

**Severity: error**

ArkTS does not support import assertions because in the language import is a
compile-time, not a runtime feature. So asserting correctness of imported APIs
in runtime does not make sense for the statically typed language. Use ordinary
``import`` syntax instead.


## TypeScript


```

    import { obj } from "something.json" assert { type: "json" }

```

## ArkTS


```

    // Correctness of importing T will be checked in compile-time:
    import { something } from "module"

```

## See also

- Recipe 129:  Wildcards in module names are not supported (``arkts-no-module-wildcards``)
- Recipe 130:  Universal module definitions (UMD) are not supported (``arkts-no-umd``)


