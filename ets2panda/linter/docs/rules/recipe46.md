#  Use arrow functions instead of function expressions

Rule ``arkts-no-func-expressions``

**Severity: error**

ArkTS does not support function expressions. Use arrow functions instead
to specify explicitly.


## TypeScript


```

    let f = function (s: string) {
        console.log(s)
    }

```

## ArkTS


```

    let f = (s: string) => {
        console.log(s)
    }

```


