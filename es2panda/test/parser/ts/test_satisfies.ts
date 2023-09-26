/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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


interface I1 {
    a: number;
}

type T1 = {
    a: "a" | "b";
}

type T2 = (x: string) => void;

const t1 = { a: 1 } satisfies I1;
const t2 = { a: 1, b: 1 } satisfies I1;
const t3 = { } satisfies I1;

const t4: T1 = { a: "a" } satisfies T1;
const t5 = (m => m.substring(0)) satisfies T2;

const t6 = [1, 2] satisfies [number, number];

interface A {
    a: string
}
let t7 = { a: 'test' } satisfies A;
let t8 = { a: 'test', b: 'test' } satisfies A;