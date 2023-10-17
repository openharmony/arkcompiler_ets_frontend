let regex: RegExp = /bc*d/

let regex2: RegExp = new RegExp("/bc*d/")

const regex3 = /^[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*(\.[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*)*$/;
const regex4: RegExp = new RegExp('^[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*(\.[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*)*$');

class A {
    static readonly classregex0: RegExp = /bc*d/

    static readonly classregex2 = /^[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*(\.[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*)*$/;

    classregex3: RegExp = new RegExp("bc*d");

    static staticMethodOne() {
        let regex = /bc*d/
    }

    static staticMethodTwo() {
        let regex: RegExp = new RegExp("/bc*d/");
    }

    methodOne() {
        let regex = /bc*d/
    }

    methodTwo() {
        let regex: RegExp = new RegExp("/bc*d/");
    }

    methodRet(): RegExp {
        return /^[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*(\.[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*)*$/;
    }
}

const regexLambda = () => /^[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*(\.[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*)*$/;
