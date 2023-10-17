#  ``export = ...`` assignment is not supported

Rule ``arkts-no-export-assignment``

**Severity: error**

ArkTS does not support ``export = ...`` syntax.
Use regular ``export`` / ``import`` instead.


## TypeScript


```

    // module1
    export = Point

    class Point {
        constructor(x: number, y: number) {}
        static origin = new Point(0, 0)
    }

    // module2
    import Pt = require("module1")

    let p = Pt.origin

```

## ArkTS


```

    // module1
    export class Point {
        constructor(x: number, y: number) {}
        static origin = new Point(0, 0)
    }

    // module2
    import * as Pt from "module1"

    let p = Pt.origin

```

## See also

- Recipe 121:  ``require`` and ``import`` assignment are not supported (``arkts-no-require``)

