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

class A {
}

interface I<T=A> {
   f(t: T): void;
}

class B implements I {
   s: string;
   f(a: A): void {}
   constructor(s: string) { this.s = s; }
}

class C<T, U = B> {
    t: T;
    u: U;
    constructor(t: T, u: U) {
        this.t = t;
        this.u = u;
    }
}
class D extends C<B> {
    f(): I[] { return [this.t, this.u]; }
}
function foo(): C<A> {
    return new C(new A(), new B(""));
}
function bar<T = A, U = B>(t: T, u: U): C<T, U> {
    return new C(t, u);
}
function zoo(): void {
    bar(new A, new B("bar"));
    bar("bar", new A);
    bar<D>(new D(new B("D"), new B("")), new B("bar"));
    bar<I, A>(new B("bar"), new A);
}
