#  Destructuring assignment is not supported

Rule ``arkts-no-destruct-assignment``

**Severity: error**

ArkTS does not support destructuring assignment. Use other idioms (e.g.,
a temporary variable, where applicable) for replacement.


## TypeScript


```

    let [one, two] = [1, 2]; // semicolon is required here
    [one, two] = [two, one]

    let head, tail
    [head, ...tail] = [1, 2, 3, 4]

```

## ArkTS


```

    let arr: number[] = [1, 2]
    let one = arr[0]
    let two = arr[1]

    let tmp = one
    one = two
    two = tmp

    let data: Number[] = [1, 2, 3, 4]
    let head = data[0]
    let tail: Number[] = []
    for (let i = 1; i < data.length; ++i) {
        tail.push(data[i])
    }

```


