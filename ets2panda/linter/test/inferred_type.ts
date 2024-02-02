/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

const [a, b, c] = [1, 'hello', true];

console.log(a);
console.log(b);
console.log(c);

function foo(): any {}

let x; // is implicitly 'Any'
let y = foo(); // is implicitly 'Any'

function bar(x) {} // 'x' is implicitly 'Any'
let baz = (x: number, y) => {}; // 'y' is implicitly 'Any'

class C {
    f; // is implicitly 'Any'
    g = foo(); // is implicitly 'Any'
    
    h(x, y, ...z) {} // 'x', 'y' and 'z' are implicitly 'Any'
}

let s1 = new Array(10);
let s2 = new Array<any>(10);
let s3 = new Array<unknown>(10);

class D {
    f; // is implicitly 'Any'
    constructor() {
        this.f = 1;
    }
}