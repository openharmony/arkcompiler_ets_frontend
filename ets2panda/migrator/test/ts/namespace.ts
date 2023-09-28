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

export namespace X {
    export class C implements I {
        private n: number;
        constructor(n: number) { this.n = n; }
        static s: string = "X.C";
    }
    export interface I {}
    export enum E {
        FAIL,
        OK
    }
    export function f(): number { return pi; }
    export let c: C = new C(f());
    export const pi = 3.1416;
    export type S = C;
    export namespace N {
        export function q(): void {}
	export class D {}
    }
    export let n = N;
}

let x = X;
function bad(): X.S {
    let c = new x.C(x.E.FAIL);
    let i = x.f();
    let s = (i !== foo().pi) ? "bad" : "good";
    try {
        bar();
    }
    catch (e) {
        let ex = e as typeof X;
        console.log(ex.C.s);
    }

    X.N.q();
    X.n.q();
    x.N.q();
    x.n.q();

    let d: X.N.D = new X.N.D;
    d = new X.n.D;
    d = new x.N.D;
    d = new x.n.D;

    return x.c;
}
function good(): X.S {
    let c: X.C = new X.C(X.E.OK);
    let i = X.f();
    if (i === X.pi) console.log("OK")
    try {
        bar();
    }
    catch (e) {
        console.log(X.C.s);
    }
    return X.c;
}
function foo(): typeof X {
    return X;
}
function bar(): never {
    throw X;
}
class BadClass1 extends x.C {}
class BadClass2 extends X.N.D {}
class BadClass3 extends x.N.D {}
class BadClass4 extends X.n.D {}
class BadClass5 extends x.n.D {}
class GoodClass extends X.C {}
