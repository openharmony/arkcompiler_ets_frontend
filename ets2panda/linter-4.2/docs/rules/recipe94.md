#  Generator functions are not supported

Rule ``arkts-no-generators``

**Severity: error**

Currently, ArkTS does not support generator functions.
Use the ``async`` / ``await`` mechanism for multitasking.


## TypeScript


```

    function* counter(start: number, end: number) {
        for (let i = start; i <= end; i++) {
            yield i
        }
    }

    for (let num of counter(1, 5)) {
        console.log(num)
    }

```

## ArkTS


```

    async function complexNumberProcessing(n : number) : Promise<number> {
        // Some complex logic for processing the number here
        return n
    }

    async function foo() {
        for (let i = 1; i <= 5; i++) {
            console.log(await complexNumberProcessing(i))
        }
    }

    foo()

```


