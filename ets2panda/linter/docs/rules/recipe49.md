#  Use generic functions instead of generic arrow functions

Rule ``arkts-no-generic-lambdas``

**Severity: error**

ArkTS does not support generic arrow functions. Use normal generic functions
instead.


## TypeScript


```

    let generic_arrow_func = <T extends String> (x: T) => { return x }

    generic_arrow_func("string")

```

## ArkTS


```

    function generic_func<T extends String>(x: T): T {
        return x
    }

    generic_func<String>("string")

```


