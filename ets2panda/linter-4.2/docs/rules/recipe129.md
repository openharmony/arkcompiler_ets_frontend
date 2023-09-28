#  Wildcards in module names are not supported

Rule ``arkts-no-module-wildcards``

**Severity: error**

ArkTS does not support wildcards in module names because in the language
import is a compile-time, not a runtime feature.
Use ordinary export syntax instead.


## TypeScript


```

    // Declaration:
    declare module "*!text" {
        const content: string
        export default content
    }

    // Consuming code:
    import fileContent from "some.txt!text"

```

## ArkTS


```

    // Declaration:
    declare namespace N {
        function foo(x: number): number
    }

    // Consuming code:
    import * as m from "module"
    console.log("N.foo called: ", N.foo(42))

```

## See also

- Recipe 128:  Ambient module declaration is not supported (``arkts-no-ambient-decls``)
- Recipe 130:  Universal module definitions (UMD) are not supported (``arkts-no-umd``)


