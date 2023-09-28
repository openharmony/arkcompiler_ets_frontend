function add(arg : double[]): double {
  return arg[0] + arg[1] + arg[2];
}

// TODO(user): unify copyBooleanArr and copyCharArr once generics are supported
function copyBooleanArr(src: boolean[]): boolean[] {
    let dst: boolean[] = new boolean[src.length];
    for (let i = 0; i < src.length; i++) {
        dst[i] = src[i];
    }
    return dst;
}

// TODO(user): unify copyBooleanArr and copyCharArr once generics are supported
function copyCharArr(src: char[]): char[] {
    let dst: char[] = new char[src.length];
    for (let i = 0; i < src.length; i++) {
        dst[i] = src[i];
    }
    return dst;
}

// TODO(user): unify cmpBooleanArr and cmpCharArr once generics are supported
function cmpBooleanArr(arg0: boolean[], arg1: boolean[]): boolean {
    if (arg0.length != arg1.length) {
        return false;
    }

    for (let i = 0; i < arg0.length; i++) {
        if (arg0[i] != arg1[i]) {
            return false;
        }
    }

    return true;
}

// TODO(user): unify cmpBooleanArr and cmpCharArr once generics are supported
function cmpCharArr(arg0: char[], arg1: char[]): boolean {
    if (arg0.length != arg1.length) {
        return false;
    }

    for (let i = 0; i < arg0.length; i++) {
        if (arg0[i] != arg1[i]) {
            return false;
        }
    }

    return true;
}

function main(): void {
  let arr : double[] = [1.1, 2.1, 3.5, 4.9];
  assert arr[0] == 1.1 && arr[1] == 2.1 && arr[2] == 3.5 && arr[3] == 4.9;
  assert add([1.1, 2.2, 3.3]) == 6.6;

  let arr2 : boolean[] = [false, true, false, true, true, false, false, true];
  assert cmpBooleanArr(copyBooleanArr(arr2), arr2);

  let arr3 : char[] = [c'a', c'b', c'c', c'd'];
  assert cmpCharArr(copyCharArr(arr3), arr3);

  return;
}
