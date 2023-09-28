function* counter(start: number, end: number) {
    for (let i = start; i <= end; i++) {
        yield i
    }
}

for (let num of counter(1, 5)) {
    console.log(num)
}


async function complexNumberProcessing(n : number) : Promise<number> {
    return n
}

async function foo() {
    for (let i = 1; i <= 5; i++) {
        console.log(await complexNumberProcessing(i))
    }
}

foo()
