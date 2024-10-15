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

import { ff } from "./oh_modules/ohos_lib";
import { f, f2, bar, applyToUnknown, fooExecute, C1, myFoo, myFoo2 } from "./dynamic_lib";

let a1: C1 = new C1()

function g1(): C1 | null {
    if (a1) {
        return a1
    }
    return null
}

f2(g1())

bar(null);
bar(null, null);
applyToUnknown(null);
fooExecute(null);

function fff(a: Array<number>): void {}

fff(null);
ff(null);
f(null);


((a: number) => a)(null);
(a: null | number) => ((b: number) => b)(a);

function inc(a: number) { return a + 1 }
function neg2null(x: number) { return x > 0 ? x : null }
inc(neg2null(-1));

myFoo({x: "", y: null})

class A2 {
    public a: Object = null
    f() {
        myFoo2(
            () => {
                this.a = null;
            }
        )
    }
}