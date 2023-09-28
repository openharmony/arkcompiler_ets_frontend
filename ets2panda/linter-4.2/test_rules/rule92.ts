function addNum(a: number, b: number): void {
    function logToConsole(message: String): void {
        console.log(message)
    }

    let result = a + b

    logToConsole("result is " + result)
}


function addNum2(a: number, b: number): void {
    // Use lambda instead of a nested function:
    let logToConsole: (message: string) => void = (message: string): void => {
        console.log(message)
    }

    let result = a + b

    logToConsole("result is " + result)
}