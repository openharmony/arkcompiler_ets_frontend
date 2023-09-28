class MyImage {
    // ...
}

function readImage(
    path: string, callback: (err: any, image: MyImage) => void
)
{
    // ...
}

function readFileSync(path : string) : number[] {
    return []
}

function decodeImageSync(contrents : number[]) {
    // ...
}

readImage.sync = (path: string) => {
    const contents = readFileSync(path)
    return decodeImageSync(contents)
}