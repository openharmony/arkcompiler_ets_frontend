#  Ambient module declaration is not supported

Rule ``arkts-no-ambient-decls``

**Severity: error**

ArkTS does not support ambient module declaration because it has its
own mechanisms for interoperating with JavaScript.


## TypeScript


```

    declare module "someModule" {
        export function normalize(s : string) : string;
    }

```

## ArkTS


```

    // Import what you need from the original module
    import { normalize } from "someModule"

```

## See also

- Recipe 129:  Wildcards in module names are not supported (``arkts-no-module-wildcards``)

