enum BarCodeFormat { A, B, C }

for (let item in BarCodeFormat) {
    console.log(item);
}

for (let i = 0; i < Object.keys(BarCodeFormat).length; i++) {
    console.log(BarCodeFormat[i]);
}

for (let i = 0; i < BarCodeFormat['C']; i++) {
    console.log(BarCodeFormat[i]);
}

for(let i = 0; i < BarCodeFormat.C; i++) {
    console.log(BarCodeFormat[i]);
}
