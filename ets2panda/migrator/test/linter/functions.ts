/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

function rest_spread() {
    const arr = [1, 2, 3];
    function Test(a, ...t) {
        console.log(a); // 1
        console.log(t[0]); // 2
        console.log(t[1]); // 3
    }
    Test(1, ...arr);
}


class MyGenerator {
    public *getValues() { // you can put the return type Generator<number>, but it is ot necessary as ts will infer 
        let index = 1;
        while(true) {
            yield index;
            index = index + 1;

            if (index > 10) {
                break;
            }
        }
    }
}

function defaultTypeParam<t, tt = string>(i: t, j: tt) {
    let c = i;
    let s = j;
}

function functionExpressionTest(): void {
    let empty = function() { };

    let multiply = function(x: number, y: number): number { return x * y; }

    function createFunc(): () => number {
        return function () { return 100; };
    }

    let foobar = function() { return "get result immediately";}();

    (function () {
        console.log("foo!");
    })();

    void function () {
        console.log("bar!");
    }();

    let factorial = function func(n: number): number {
        return (n === 1) ? 1 : n * func(n - 1);
    }

    let array = [1, 2, 3, 4, 5, 6];
    let double = array.map(function(e) { return e * 2; });
    let even = array.filter(function(x) { return x % 2 === 0; });

    let generic = function <T, E> (t: T, e: E) { return t; };
}

function arrowFunctionTest() {
    let empty = () => { }; // no return type

    let double = (x: number) => x * 2; // no return type

    let square = (x): number => x * x; // no param type

    let sqrt = x => Math.sqrt(x); // shortcut syntax
    let even = [1, 2, 3, 4, 5, 6].filter(x => x % 2 === 0); // shortcut syntax

    let foo = (x: number, y): boolean => x == y; // types are partly omitted

    let generic = <T, E> (t: T, e: E) => t; // Generic lambda
}

function fooThis(i: number): void {
    this.c = 10;
}
class C {
    c: number;
    m = fooThis;
}

function choose<T>(x: T, y: T): T {
    return Math.random() < 0.5 ? x : y;
}
let choice1 = choose(10, 20);
let choice2 = choose<string>("apple", "orange");

class Collection<T> {
    items: T[] = [];

    constructor(...args: T[]) {
        if (!args) return;
        
        for (const arg of args) 
            this.items.push(arg);
    }
}
let col = new Collection<number>(1, 2, 3);
let col2 = new Collection("a", "b", "c");