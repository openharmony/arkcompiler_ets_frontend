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

@Sendable
class A {
}

interface GeneratedObjectLiteralInterface_1 {
    e1: number;
    e2: string;
}
@Sendable
class B {
    // fixable
    a: number = 0;
    static b: string = ' ';
    private c: undefined = undefined;
    public static d: A = new A();
    e?: number | undefined = 10;
    f: number[] = [1, 2, 3];

    // not fixable
    bad;

    ehelper1: number = 4;
    ehelper2: string = 'abc';
    public bad3: GeneratedObjectLiteralInterface_1 = {
        e1: this.ehelper1,
        e2: this.ehelper2
    };

    constructor(x: boolean) {
        this.bad = x;
    }
}
