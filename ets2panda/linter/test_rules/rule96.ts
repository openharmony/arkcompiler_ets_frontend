class Foo {
    foo: number = 0
    common: string = ""
}

class Bar {
    bar: number = 0
    common: string = ""
}

function isFoo(arg: any): arg is Foo {
    return arg.foo !== undefined
}

function doStuff(arg: Foo | Bar) {
    if (isFoo(arg)) {
        console.log(arg.foo)    // OK
        console.log(arg.bar)    // Compile-time error
    } else {
        console.log(arg.foo)    // Compile-time error
        console.log(arg.bar)    // OK
    }
}

doStuff({ foo: 123, common: '123' })
doStuff({ bar: 123, common: '123' })


function isFoo2(arg: Object): boolean {
    return arg instanceof Foo
}

function doStuff2(arg: Object): void {
    if (isFoo2(arg)) {
        let fooArg = arg as Foo
        console.log(fooArg.foo)     // OK
        console.log(arg.bar)        // Compile-time error
    } else {
        let barArg = arg as Bar
        console.log(arg.foo)        // Compile-time error
        console.log(barArg.bar)     // OK
    }
}

function main(): void {
    doStuff2(new Foo())
    doStuff2(new Bar())
}