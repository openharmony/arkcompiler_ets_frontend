#  Special import type declarations are not supported

Rule ``arkts-no-special-imports``

**Severity: error**

ArkTS does not have a special notation for importing types.
Use ordinary import instead.


## TypeScript


```

    // Re-using the same import
    import { APIResponseType } from "api"

    // Explicitly use import type
    import type { APIResponseType } from "api"

```

## ArkTS


```

    import { APIResponseType } from "api"

```

## See also

- Recipe 119:  Importing a module for side-effects only is not supported (``arkts-no-side-effects-imports``)
- Recipe 120:  ``import default as ...`` is not supported (``arkts-no-import-default-as``)
- Recipe 121:  ``require`` and ``import`` assignment are not supported (``arkts-no-require``)


