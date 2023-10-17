#  ``require`` and ``import`` assignment are not supported

Rule ``arkts-no-require``

**Severity: error**

ArkTS does not support importing via ``require``.
``import`` assignments are not supported either.
Use regular ``import`` instead.


## TypeScript


```

    import m = require("mod")

```

## ArkTS


```

    import * as m from "mod"

```

## See also

- Recipe 126:  ``export = ...`` assignment is not supported (``arkts-no-export-assignment``)



