/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
    n: number // Compile-time error only with strictPropertyInitialization
    s: string // Compile-time error only with strictPropertyInitialization
}

// Compile-time error only with noImplicitReturns
function foo(s: string): string {
    if (s != "") {
        console.log(s)
        return s
    } else {
        console.log(s)
    }
}

let n: number = null // Compile-time error only with strictNullChecks

function bar(): number {
}

function get1(): boolean {
    return true;
}
function get2(): boolean {
    return false;
}

function solve(): boolean {
    if(get1() && get2()) {
    } else if(!get2()) {
        return true;
    } else {
    }
}



let lr = (): number => {}
let le = (): number => { if(get()) return 1; }

class testClass {
    static readonly lem =  (): number => { if(get()) return 1; }

    solve(): boolean {
        if(get1() && get2()) {
        } else if(!get2()) {
            return true;
        } else {
        }
    }
}
