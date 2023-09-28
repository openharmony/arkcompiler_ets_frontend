class Klass {
    private constructor() {
        this.a = 2;
    }

    private a: int = 1;
}

function main(): void {
    let klass: Klass = new Klass();
}
