#  It is possible to spread only arrays or classes derived from arrays into the rest parameter or array literals

Rule ``arkts-no-spread``

**Severity: error**

The only supported scenario for the spread operator is to spread an array or
class derived from array into the rest parameter or array literal.
Otherwise, manually "unpack" data from arrays and objects, where necessary.
All typed arrays from the standard library (for example, ``Int32Array``)
are also supported.


## TypeScript


```

    function foo(x : number, y : number, z : number) {
        console.log(x, y, z)
    }

    let args : [number, number, number] = [0, 1, 2]
    foo(...args)

    let list1 = [1, 2]
    let list2 = [...list1, 3, 4]

    let point2d = {x: 1, y: 2}
    let point3d = {...point2d, z: 3}

```

## ArkTS


```

    function sum_numbers(...numbers: number[]): number {
        let res = 0
        for (let n of numbers)
            res += n
        return res
    }
    console.log(sum_numbers(1, 2, 3))

    function log_numbers(x : number, y : number, z : number) {
        console.log(x, y, z)
    }
    let numbers: number[] = [1, 2, 3]
    log_numbers(numbers[0], numbers[1], numbers[2])

    let list1 : number[] = [1, 2]
    let list2 : number[] = [list1[0], list1[1], 3, 4]

    class Point2D {
        x: number = 0; y: number = 0
    }

    class Point3D {
        x: number = 0; y: number = 0; z: number = 0
        constructor(p2d: Point2D, z: number) {
            this.x = p2d.x
            this.y = p2d.y
            this.z = z
        }
    }

    let p3d = new Point3D({x: 1, y: 2} as Point2D, 3)
    console.log(p3d.x, p3d.y, p3d.z)

    class DerivedFromArray extends Uint16Array {};

    let arr1 = [1, 2, 3];
    let arr2 = new Uint16Array([4, 5, 6]);
    let arr3 = new DerivedFromArray([7, 8, 9])
    let arr4 = [...arr1, 10, ...arr2, 11, ...arr3]

```


