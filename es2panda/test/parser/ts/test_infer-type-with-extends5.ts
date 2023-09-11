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


type T19<T extends string | number> = T extends (infer U extends number) ? [T, U] : never;
type X19_T1 = T19<"a">; // never
type X19_T2 = T19<1>; // [1, 1]
type X19_T3 = T19<1 | "a">; // [1, 1]

type T20<T> = T extends (infer U extends number) ? T extends (infer V extends U) ? [T, U, V] : never : never;
type X20_T1 = T20<1 | "a">; // [1, 1, 1]

type T21<T, N extends number> = T extends (infer U extends N) ? [T, U] : never;
type X21_T1 = T21<1, 1>; // [1, 1]
type X21_T2 = T21<1 | "a", 1>; // [1, 1]
type X21_T3 = T21<1 | 2, 1>; // [1, 1]
type X21_T4 = T21<1 | 2, 2 | 3>; // [2, 2]
type X21_T5 = T21<1 | 2, 3>; // never

// from mongoose
type IfEquals<X, Y, A, B> = (<T>() => T extends X ? 1 : 2) extends <T>() => T extends Y ? 1 : 2 ? A : B;

declare const val1: <T>() => (T extends infer U extends number ? 1 : 0);
function func1() {
    return val1;
}

type ExpectNumber<T extends number> = T;
declare const val2: <T>() => (T extends ExpectNumber<infer U> ? 1 : 0);
function fun2() {
    return val2;
}

type X22<T> = T extends [infer U extends number, infer U extends number] ? string : never;

type U =1
type c<T> = T extends [infer s extends U extends number ? 1:2 ]? 1:2