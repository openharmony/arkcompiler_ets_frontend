type DescribableFunction = {
    description: string
    (someArg: number): string // call signature
}

function doSomething(fn: DescribableFunction): void {
    console.log(fn.description + " returned " + fn(6))
}