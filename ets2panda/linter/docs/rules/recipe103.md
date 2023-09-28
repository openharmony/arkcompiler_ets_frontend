#  Declaration merging is not supported

Rule ``arkts-no-decl-merging``

**Severity: error**

ArkTS does not support merging declarations. Keep all definitions of classes
and interfaces compact in the codebase.


## TypeScript


```

    interface Document {
        createElement(tagName: any): Element
    }

    interface Document {
        createElement(tagName: string): HTMLElement
    }

    interface Document {
        createElement(tagName: number): HTMLDivElement
        createElement(tagName: boolean): HTMLSpanElement
        createElement(tagName: string, value: number): HTMLCanvasElement
    }

```

## ArkTS


```

    interface Document {
        createElement(tagName: number): HTMLDivElement
        createElement(tagName: boolean): HTMLSpanElement
        createElement(tagName: string, value: number): HTMLCanvasElement
        createElement(tagName: string): HTMLElement
        createElement(tagName: Object): Element
    }

```


