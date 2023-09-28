interface ListItem {
    getHead(): this
}

class C {
    n: number = 0

    m(c: this) {
        console.log(c)
    }
}

interface ListItem2 {
    getHead(): ListItem
}

class D {
    n: number = 0

    m(c: D) {
        console.log(c)
    }
}