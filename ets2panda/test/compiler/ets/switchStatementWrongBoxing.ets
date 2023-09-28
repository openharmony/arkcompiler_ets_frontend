class A {
    foo(): void{
        let a: Int = 200000;
        const b: byte = 20;
        switch(a){
            case b:
                // byte to Integer error
                break;
            case c'k':
                // char to Integer error
        }
    }
}
