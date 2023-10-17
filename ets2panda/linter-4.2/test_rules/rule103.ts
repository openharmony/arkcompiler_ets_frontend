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