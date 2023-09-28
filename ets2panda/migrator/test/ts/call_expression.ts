/*
 * Copyright (c) 2022-2022 Huawei Device Co., Ltd.
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

function main(): void {
    let x = square(10) + square(20);
    strings("The sky is blue!", "sky");

    let cObj = new C();
    cObj.nothing();
    let y = cObj.sum(5, 10);

    let dObj = new D();
    dObj.field.sum(100, 200);
}

function square(a: number): number {
    return a * a;
}

function strings(s1: string, s2: string): void {
    let s3 = s1.substring(1, s1.length - 2);
    let s4 = s1.toLowerCase().replace(s2.toLowerCase(), "replacement");
}

class C {
    nothing(): void {}

    sum(a: number, b: number): number {
        return a + b;
    }
}
class D {
    field: C;
}