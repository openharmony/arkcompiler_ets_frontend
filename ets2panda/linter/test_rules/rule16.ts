class C {
    static s: string

    static {
        C.s = "aa"
    }
    static {
        C.s = C.s + "bb"
    }
}

class D {
    static s: string

    static {
        D.s = "aa"
        D.s = D.s + "bb"
    }
}