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

const num: int = 1;
const param: int = 2;

class A {
    static invoke(): int {
        return num;
    }
}

class B extends A {

}

class C extends A {
    static invoke(a: int): int {
        return a;
    }
}

class D extends A {
    static invoke(cb: ()=>void): int {
        cb();
        return num;
    }
}

function call_static_invoke_method() {
    assert A() == num : "expected: " + num + " actual: " + A();
    assert B() == num : "expected: " + num + " actual: " + B();
    assert C(param) == param : "expected: " + param + " actual: " + C(param);
    let d = D() {};
    assert d == num : "expected: " + num + " actual: " + d;
}

class Z {
    z_: int = 0;

    build(): int {
        return this.z_;
    }

    static instantiate<T extends Z>(factory: ()=>T): T {
        let z = factory();
        z.build();
        return z;
    }
}

class Y {
    static instantiate<T extends Y>(factory: ()=>T, num: int): T {
        num++;
        let y = factory();
        return y;
    }
}

function call_static_instantiate_method() {
    Z();
    Y(1);
}

function main() {
    call_static_invoke_method();
    call_static_instantiate_method();
}
