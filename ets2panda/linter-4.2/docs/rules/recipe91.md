#  Destructuring parameter declarations are not supported

Rule ``arkts-no-destruct-params``

**Severity: error**

ArkTS requires parameters to be passed directly to the function, and
local names to be assigned manually.


## TypeScript


```

    function drawText({ text = "", location: [x, y] = [0, 0], bold = false }) {
        console.log(text)
        console.log(x)
        console.log(y)
        console.log(bold)
    }

    drawText({ text: "Hello, world!", location: [100, 50], bold: true })

```

## ArkTS


```

    function drawText(text: String, location: number[], bold: boolean) {
        let x = location[0]
        let y = location[1]
        console.log(text)
        console.log(x)
        console.log(y)
        console.log(bold)
    }

    function main() {
        drawText("Hello, world!", [100, 50], true)
    }

```


