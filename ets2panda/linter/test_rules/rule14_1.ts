class DescribableFunction {
    description: string
    public invoke(someArg: number): string {
        return someArg.toString()
    }
    constructor() {
        this.description = "desc"
    }
}

function doSomething(fn: DescribableFunction): void {
    console.log(fn.description + " returned " + fn.invoke(6))
}

doSomething(new DescribableFunction())