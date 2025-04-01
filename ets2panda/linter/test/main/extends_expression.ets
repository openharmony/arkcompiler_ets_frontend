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
class A {
  v: number = 0
}

let a = A

class B extends a {
  u: number = 0
}

class Control {
    state: number = 0;
}

interface SelectableControl extends Control {
    select(): void;
}

interface C {
    foo(): void;
}

class C1 implements C {
    foo() {}
}

interface E {
    foo(): void;
}

let e = E

class C3 implements e {
    foo() {}
}

class C4 implements E {
    foo() {}
}

export declare class Bar<T extends Something> {
    constructor(arg: { new(): T });
}