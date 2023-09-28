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

interface I {
    m(): number;
} 

function main(): void {
    function empty() { }
    empty();

    function multiply(x: number, y: number): number {
        return x * y;
    }
    console.log(multiply(5, 10));

    function filter(array: number[], predicate: (x: number) => boolean): number[] {
        let newArray: number[] = [];
        for (let element of array) {
            if (predicate(element))
                newArray.push(element);
        }
        return newArray;
    }
    function isOdd(x: number) {
        return x % 2 !== 0;
    }
    let odd = filter([1, 2, 3, 4, 5, 6], isOdd);

    // Rest parameter
    function restParam(x: number, y: number, ...rest: number[]) { 
        for (let z of rest) {
            console.log(x + y + z);
        }
    }
    restParam(1, 2);
    restParam(1, 2, 3);
    restParam(1, 2, 3, 4);
    restParam(1, 2, 3, 4, 5);

    // Recursive
    function factorial(n: number): number {
        if (n === 1)
            return 1;
        else
            return n * factorial(n - 1);
    }
    console.log(factorial(5));

    // Generic
    function generic1<T, E>(t: T, e: E) { return t; };
    generic1(100, "apple");
    let foo: string = generic1<string, string>("arg1", "arg2");

    function generic2<W extends I>(w: W): void {
        w.m();
    }
    generic2({ m() { return 10; } });
}
