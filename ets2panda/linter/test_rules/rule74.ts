class Point {
    x: number = 0.0
    y: number = 0.0
}

function returnZeroPoint(): Point {
    return new Point()
}

let {x, y} = returnZeroPoint()



function returnZeroPoint2(): Point {
    return new Point()
}

let zp = returnZeroPoint2()
let x2 = zp.x
let y2 = zp.y