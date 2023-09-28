interface StringArray {
    [index: number]: string
}

function getStringArray() : StringArray {
    return ["a", "b", "c"]
}

const myArray: StringArray = getStringArray()
const secondItem = myArray[1]

class Y {
    public f: string[] = []
}

let myArray2: Y = new Y()
const secondItem2 = myArray2.f[1]