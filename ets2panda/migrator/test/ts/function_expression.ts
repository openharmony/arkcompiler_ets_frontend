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

function createFunc(): () => number {
    return function () { return 100; };
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
    let empty = function() { };
    empty();

    let multiply = function(x: number, y: number): number { return x * y; }
    console.log(multiply(5, 10));

    let foo = createFunc();
    let a: number = foo();
    let b: number = createFunc()();

    // Infer parameter's and return type.
    let bar: MyFunction = function(x, y) { return "value"; };
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
    let foobar = function() { return "get result immediately";}();

    (function () {
        console.log("foo!");
    })();
      
    void function () {
        console.log("bar!");
    }();

    !function () { return false; }();
    
    +function () { return 0; }();

    // Named function expression with recursive call.
    let factorial = function func(n: number): number {
        if (n === 1)
            return 1;
        else
            return n * func(n - 1);
    }
    console.log(factorial(5));
    
    // Function as a callback.
    let array = [1, 2, 3, 4, 5, 6];
    let double = array.map(function(e) { return e * 2; });
    let even = filter(array, function(x) { return x % 2 === 0; });
    let isOdd = function(x: number) { return x % 2 !== 0; };
    let odd = filter(array, isOdd);

    // Generic function expression.
    let generic1 = function <T, E> (t: T, e: E) { return t; };
    generic1(100, "apple");
    let baz: string = generic1<string, string>("arg1", "arg2");

    let generic2 = function <W extends I> (w: W): void {
        w.m();
    }
    generic2({ m() { return 10; } });
}
