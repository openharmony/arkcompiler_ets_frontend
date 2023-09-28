/*
 * Copyright (c) 2022-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */ 

type MyFunction = (x: number, y: boolean) => string; 

interface I {
    m(): number;
}

function createLambda(): () => number {
    return () => 10;
}

function filter(array: number[], predicate: (x: number) => boolean): number[] {
    let newArray: number[] = [];
    for (let element of array) {
        if (predicate(element))
            newArray.push(element);
    }
    return newArray;
}

function main(): void {
    let empty = () => { };
    empty();

    let double: (x: number) => number = x => x * x;
    console.log(double(10));

    let foo = createLambda();
    let a: number = foo();
    let b: number = createLambda()();

    // Infer parameter's and return type.
    let bar: MyFunction = (x, y) => "value";
    console.log(bar(10, true));

    let restParam = (x: number, y: number, ...rest: number[]) => { 
        for (let z of rest) {
            console.log(x + y + z);
        }
    }
    restParam(1, 2);
    restParam(1, 2, 3);
    restParam(1, 2, 3, 4);
    restParam(1, 2, 3, 4, 5);

    // Immediately invoked function expression
    (() => "foobar")();

    // Recursive lambda
    let factorial = (n: number): number => {
        if (n === 1)
            return 1;
        else
            return n * factorial(n - 1);
    }
    console.log(factorial(5));
    
    let array = [1, 2, 3, 4, 5, 6];
    let square = array.map((e) => e * e);
    let even = filter(array, x => x % 2 === 0);

    // Generic arrow functions.
    let generic = <T, E> (t: T, e: E) => t;
    generic(100, "apple");
    let baz: string = generic<string, number>("orange", 25);

    let generic2 = <W extends I> (w: W): void => {
        w.m();
    }
    generic2({ m() { return 0; } })
}
