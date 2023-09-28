#  Declaring properties on functions is not supported

Rule ``arkts-no-func-props``

**Severity: error**

ArkTS does not support declaring properties on functions because there is no
support for objects with dynamically changing layout. Function objects follow
this rule and their layout cannot be changed in runtime.


## TypeScript


```

    class MyImage {
        // ...
    }

    function readImage(
        path: string, callback: (err: any, image: MyImage) => void
    )
    {
        // ...
    }

    function readFileSync(path : string) : number[] {
        return []
    }

    function decodeImageSync(contents : number[]) {
        // ...
    }

    readImage.sync = (path: string) => {
        const contents = readFileSync(path)
        return decodeImageSync(contents)
    }

```

## ArkTS


```

    class MyImage {
        // ...
    }

    async function readImage(
        path: string, callback: (err: Error, image: MyImage) => void
    ) : Promise<MyImage>
    {
        // In real world, the implementation is more complex,
        // involving real network / DB logic, etc.
        return await new MyImage()
    }

    function readImageSync(path: string) : MyImage {
        return new MyImage()
    }

```

## See also

- Recipe 137:  ``globalThis`` is not supported (``arkts-no-globalthis``)


