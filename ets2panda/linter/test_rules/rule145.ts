class C {
    n: number // Compile-time error only with strictPropertyInitialization
    s: string // Compile-time error only with strictPropertyInitialization
}

// Compile-time error only with noImplicitReturns
function foo(s: string): string {
    if (s != "") {
        console.log(s)
        return s
    } else {
        console.log(s)
    }
}

let n: number = null // Compile-time error only with strictNullChecks

function bar(): number {
}

function get1(): boolean {
    return true;
}
function get2(): boolean {
    return false;
}

function solve(): boolean {
    if(get1() && get2()) {
    } else if(!get2()) {
        return true;
    } else {
    }
}



let lr = (): number => {}
let le = (): number => { if(get()) return 1; }

class testClass {
    static readonly lem =  (): number => { if(get()) return 1; }

    solve(): boolean {
        if(get1() && get2()) {
        } else if(!get2()) {
            return true;
        } else {
        }
    }
}
