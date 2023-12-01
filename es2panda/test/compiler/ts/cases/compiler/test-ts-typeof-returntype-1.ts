class MainAbility {
    public static test(fn, thisArg): (args: Parameters<typeof fn>) => void {
        return function extendFn() {
            fn.apply(thisArg);
        };
    }
}

function fun(){
    print("hello world");
}

MainAbility.test(fun,1)([]);