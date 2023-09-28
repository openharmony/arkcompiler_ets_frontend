#  Importing a module for side-effects only is not supported

Rule ``arkts-no-side-effects-imports``

**Severity: error**

ArkTS does not support global variables like ``window`` to avoid
side-effects during module importing. All variables marked as export can be
accessed through the ``*`` syntax.


## TypeScript


```

    // === module at "path/to/module.ts"
    export const EXAMPLE_VALUE = 42

    // Set a global variable
    window.MY_GLOBAL_VAR = "Hello, world!"

    // ==== using this module:
    import "path/to/module"

```

## ArkTS


```

    import * as m from "path/to/module"

```


