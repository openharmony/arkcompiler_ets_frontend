class A {
    bar(a0: int): void{
        let func: (a1: int) => void = (a1: int): void => {
            console.print("bar.func");
        }
        this.classf(func);
    }

    functest(func: (a1: int) => void): void {
        func(2);
    }

    sim_print(): void {
        console.print("sim_print");
    }

    classf(locfunc: (a1: int) => void): void {
        this.functest(locfunc);
        this.functest( (a1: int): void => { console.print("lambda_func") } );
        let capture_param: () => void = (): void => {
            locfunc(2);
        }
        let capture_this: () => void = (): void => {
            this.sim_print();
        }
        this.functest((a1: int): void => {
            locfunc(2);
        });
        locfunc(3);
    }
}

function main(): void {
    let testClass: A = new A();
    testClass.bar(2);
}
