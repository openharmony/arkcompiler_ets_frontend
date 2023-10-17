function drawText({ text = "", location: [x, y] = [0, 0], bold = false }) {
    console.log(text)
    console.log(x)
    console.log(y)
    console.log(bold)
}

drawText({ text: "Hello, world!", location: [100, 50], bold: true })


function drawText1(text: String, location: number[], bold: boolean) {
    let x = location[0]
    let y = location[1]
    console.log(text)
    console.log(x)
    console.log(y)
    console.log(bold)
}

function main() {
    drawText1("Hello, world!", [100, 50], true)
}