    // module1
    export = Point

    class Point {
        constructor(x: number, y: number) {}
        static origin = new Point(0, 0)
    }

    // module2
    import Pt = require("module1")

    let p = Pt.origin
