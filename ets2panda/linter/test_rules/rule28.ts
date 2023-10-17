type Point = {x: number, y: number}
type N = Point["x"] // is equal to number

class Point2 {x: number = 0; y: number = 0}
type N2 = number