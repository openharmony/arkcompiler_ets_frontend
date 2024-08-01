/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

class MyType {
    x: int = 10;
    constructor() { }
    constructor(a: int) {
        this.x = a;
    }
}

function main(): void {
    assert foo1() == 8;

    assert foo2() == 30;
    assert foo2(new MyType(5)) == 25;

    assert foo3(new MyType(5)) == 55;
    assert foo3(new MyType(5), new MyType(10)) == 45;

    assert foo4() == 0;

    assert foo5() == 0;
    assert foo5(new MyType(5)) == -1;

    assert foo6(new MyType(5)) == 0;
    assert foo6(new MyType(5), new MyType(10)) == -1;

    assert foo7() == 0;
    assert foo8() == 0;

    assert foo9(new MyType(10)) == 15;
    assert foo10(new MyType(10)) == 25;

    assert foo11(new MyType(10), new MyType(5)) == 20;
    assert foo12(new MyType(10), new MyType(5)) == 30;
}

function foo1(a: MyType|null = new MyType(8)): int {
    if (a == null) {
        return -1;
    }
    return a.x;
}

function foo2(a: MyType = new MyType(10), b: MyType = new MyType(20)): int {
    return a.x + b.x;
}

function foo3(a: MyType = new MyType(10), b: MyType = new MyType(20), c: MyType = new MyType(30)): int {
    assert a.x == 5;

    return a.x + b.x + c.x;
}

function foo4(a?: MyType): int {
    if (a == null) {
        return 0;
    }
    return a.x;
}

function foo5(a?: MyType, b?: MyType): int {
    if (a == null && b == null) {
        return 0;
    }
    if (b == null) {
        return -1;
    }
    return a!.x + b.x;
}

function foo6(a?: MyType, b?: MyType, c?: MyType): int {
    assert a!.x == 5;
    if (b == null && c == null) {
        return 0;
    }
    if (c == null) {
        return -1;
    }

    return a!.x + b!.x + c.x;
}

function foo7(a: MyType = new MyType(5), b?: MyType): int {
    if (b == null) {
        return 0;
    }
    return a.x + b.x;
}

function foo8(a?: MyType, b: MyType = new MyType(5), c?: MyType): int {
    assert b.x == 5;

    if (a == null && c == null) {
        return 0;
    }

    return a!.x + b.x + c!.x;
}

function foo9(a: MyType, b: MyType = new MyType(5)): int {
    return a.x + b.x;
}

function foo10(a: MyType, b: MyType = new MyType(5), c: MyType = new MyType(10)): int {
    return a.x + b.x + c.x;
}

function foo11(a: MyType, b: MyType, c: MyType = new MyType(5)): int {
    return a.x + b.x + c.x;
}

function foo12(a: MyType, b: MyType, c: MyType = new MyType(10), d: MyType = new MyType(5)): int {
    return a.x + b.x + c.x + d.x;
}
