class Point {
    x?: number = 0.0
    y?: number = 0.0
}

let p = new Point()
delete p.y

class Point2 {
    x: number | null = 0
    y: number | null = 0
}

let p2 = new Point()
p2.y = null