/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

class B<T> {
    value: T;
    x:T;
    constructor(value: T) {
        this.value = value;
    }
}

type FB<T> = (this: B<T>, x: T) => T;
type FBSI = (this: B<string|Int>, x: string|Int) => string|Int;

function apply(bb: B<string|Int>[], ff: FBSI) {
    for (let b of bb) {
        assertEQ(b.ff("hello"), b.value)
        assertEQ(ff(b, "hello"), b.value)
    }
}
let bb: B<string|Int>[] = [new B<string|Int>("aa"), new B<string|Int>(1)]
apply(bb, (this: B<string|Int>, x: string|Int): string|Int => {this.x = x; return this.value;} )
