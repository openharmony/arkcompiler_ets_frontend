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
    v: int = 0;
    constructor (v: int) {
        this.v = v;
    }
}

function part0() {
    let b = false
    let lam: () => void = () => {
        assertEQ(b, true)
        b = false
    }
    b = true
    lam()
    assertEQ(b, false)
}

function part1() {
    let b: byte = 0;
    let s: short = 0;
    let i: int = 0;
    let c: char = 0;
    let lam: () => void = () => {
        assertEQ(b, 1)
        assertEQ(s, 2)
        assertEQ(i, 3)
        assertEQ(c, 4)
        b = 5;
        s = 6;
        i = 7;
        c = 8;
    };
    b = 1;
    s = 2;
    i = 3;
    c = 4;
    lam();
    assertEQ(b, 5)
    assertEQ(s, 6)
    assertEQ(i, 7)
    assertEQ(c, 8)
}

function part2() {
    let l: long = 0;
    let f: float = 0.0;
    let d: double = 0.0;
    let o = new C(0);
    let lam: () => void = () => {
        assertEQ(l, 9)
        assertEQ(f, 10.0)
        assertEQ(d, 11.0)
        assertEQ(o.v, 12)
        l = 13;
        f = 14.0;
        d = 15.0;
        o = new C(16);
    }
    l = 9;
    f = 10.0;
    d = 11.0;
    o = new C(12);
    lam();
    assertEQ(l, 13)
    assertEQ(f, 14.0)
    assertEQ(d, 15.0)
    assertEQ(o.v, 16)
}

function main(): void {
    part0();
    part1();
    part2();
    return;
}
