#  Non-declaration statements in namespaces are not supported

Rule ``arkts-no-ns-statements``

**Severity: error**

ArkTS does not support statements in namespaces. Use a function to execute
statements.


## TypeScript


```

    namespace A {
        export let x: number
        x = 1
    }

```

## ArkTS


```

    namespace A {
        export let x: number

        export function init() {
          x = 1
        }
    }

    // Initialization function should be called to execute statements:
    A.init()

```


