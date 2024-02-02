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

class I<T> { }

type A = I<A>;
(fn: () => A) => { let x = fn() }
(fn: () => I<I<I<A> | A> | null> | I<A>) => { let x = fn() }

type B = I<I<I<A>>>;
(fn: () => B) => { let x = fn() }

type C = I<I<I<C>>>;
(fn: () => C) => { let x = fn() }

class X1 extends I<X1> { };
(fn: () => X1) => { let x = fn() }

class X2 extends I<I<number | X2> | null> { };
(fn: () => X2) => { let x = fn() }

type D = string | I<D | number>;
(fn: () => D) => { let x = fn() }

namespace test1 {
    type A = string | Array<A> | Map<string, A | Array<A>>;

    class C {
        private f(): A {
            let t = this.f();
            return "";
        };
    }
}

namespace test2 {
    type A = string | Array<A> | Map<string, A | Array<A>>;

    function f(): A {
        return ""
    }
    let b = f();
}

namespace test3 {
    export type NVal = string | Array<NVal> | Map<string, NVal | Array<NVal>>;

    class NParser {
        private upd(name: string, value: NVal, parent: Map<string, NVal>) {
            if (parent.has(name)) {
                let cur = parent.get(name);
                if (cur instanceof Array) {
                    (cur as Array<object | string>).push(value);
                } else if (cur != undefined) {
                    let array = [cur, value];
                    parent.set(name, array);
                }
            } else {
                parent.set(name, value);
            }
        }
    }
}

type E = [E];
(fn: () => E) => { let x = fn() }

type F1 = () => F1;
(fn: () => F1) => { let x = fn() }

type F2 = (a: F2 | number | F2[]) => F2 | Array<F2 | Array<(F2 | string)[]> | string>;
(fn: () => F2) => { let x = fn() }
