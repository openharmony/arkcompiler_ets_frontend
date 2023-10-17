#  The comma operator ``,`` is supported only in ``for`` loops

Rule ``arkts-no-comma-outside-loops``

**Severity: error**

ArkTS supports the comma operator ``,`` only in ``for`` loops. Otherwise,
it is useless as it makes the execution order harder to understand.


## TypeScript


```

    for (let i = 0, j = 0; i < 10; ++i, j += 2) {
        console.log(i)
        console.log(j)
    }

    let x = 0
    x = (++x, x++) // 1

```

## ArkTS


```

    for (let i = 0, j = 0; i < 10; ++i, j += 2) {
        console.log(i)
        console.log(j)
    }

    // Use explicit execution order instead of the comma operator:
    let x = 0
    ++x
    x = x++

```


