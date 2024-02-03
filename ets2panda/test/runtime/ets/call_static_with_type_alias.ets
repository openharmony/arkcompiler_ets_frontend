/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

interface I {
    static inc(p: number): number {
        return p + 1;
    }
}

class C1 {
    static inc2(p: number): number {
        return p + 2;
    }
}

class C2 implements I {
}

type TI = I;
type TTI = TI;

type TC1 = C1;
type TTC1 = TC1;

type TC2 = C2;
type TTC2 = TC2;

function main(): void {
    assert I.inc(20) == 21;
    assert TI.inc(20) == 21;
    assert TTI.inc(20) == 21;

    assert C1.inc2(20) == 22;
    assert TC1.inc2(20) == 22;
    assert TTC1.inc2(20) == 22;

    assert C2.inc(20) == 21;
    assert TC2.inc(20) == 21;
    assert TTC2.inc(20) == 21;
}
