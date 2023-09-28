/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

class C {
    a: any;
    b: any[];
    c: [number, number];
    d: number[];
}

function array_literals(): void {
    // Variable declaration
    let a = [1, 2];                     // NOT OK
    let b: any = [3, 4];                // NOT OK
    let c: any[] = [5, 6];              // OK
    let d: [number, number] = [7, 8];   // NOT OK
    let e: number[] = [9, 10];          // OK
    let f = [1, "x", true];             // NOT OK
    let g: Object[] = [2, "y", false];  // OK

    let h: C = {
        a: [1, 2],     // NOT OK
        b: [3, 4],     // OK
        c: [5, 6],     // NOT OK
        d: [7, 8]      // OK
    };

    let x = [1, 2, 3][1];   // NOT OK
    
    // Assignment
    a = [1, 2];             // OK (at this point, variable is known to be the 'number[]' type)
    b = [3, 4];             // NOT OK
    c = [5, 6];             // OK
    d = [7, 8];             // NOT OK
    e = [9, 10];            // OK
    f = [1, "x", true];     // NOT OK
    g = [2, "y", false];    // OK

    h = {
        a: [1, 2],     // NOT OK
        b: [3, 4],     // OK
        c: [5, 6],     // NOT OK
        d: [7, 8]      // OK
    };

    // Default parameter value
    function foo(x = [1, 2]) { }                        // NOT OK
    function foo2(x: any = [3, 4]) { }                  // NOT OK
    function foo3(x: any[] = [5, 6]) { }                // OK
    function foo4(x: [number, number] = [7, 8]) { }     // NOT OK
    function foo5(x: number[] = [9, 10]) { }            // OK

    // Function call
    foo([1, 2]);    // OK
    foo2([3, 4]);   // NOT OK
    foo3([5, 6]);   // OK
    foo4([7, 8]);   // NOT OK
    foo5([9, 10]);  // OK

    // Return from function
    function bar() { return [1, 2]; }                       // NOT OK
    function bar2(): any { return [3, 4]; }                 // NOT OK
    function bar3(): any[] { return [5, 6]; }               // OK
    function bar4(): [number, number] { return [7, 8]; }    // NOT OK
    function bar5(): number[] { return [9, 10]; }           // OK

    // In ternary operator
    let condition = true;
    a = (condition) ? [1, 2] : [3, 4];          // OK
    b = (condition) ? [5, 6] : [7, 8];          // NOT OK
    c = (condition) ? [9, 10] : [11, 12];       // OK
    d = (condition) ? [13, 14] : [15, 16];      // NOT OK
    e = (condition) ? [17, 18] : [19, 20];      // OK
}