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


type X7_T1 = T7<{ a: "a", b: "b" }>; // ["string", "a" | "b"]
type X7_T2 = T7<{ a: 1, b: 2 }>; // ["number", 1 | 2]
type X7_T3 = T7<{ a: object, b: object }>; // never
type X7_T4 = T7<{ a: "a", b: 1 }>; // never

// infer twice with missing second constraint (same behavior as class/interface)
type T8<T> =
    T extends { a: infer U extends string, b: infer U } ? ["string", U] :
    T extends { a: infer U extends number, b: infer U } ? ["number", U] :
    never;

type X8_T1 = T8<{ a: "a", b: "b" }>; // ["string", "a" | "b"]
type X8_T2 = T8<{ a: 1, b: 2 }>; // ["number", 1 | 2]
type X8_T3 = T8<{ a: object, b: object }>; // never
type X8_T4 = T8<{ a: "a", b: 1 }>; // never

// infer twice with missing first constraint (same behavior as class/interface)
type T9<T> =
    T extends { a: infer U, b: infer U extends string } ? ["string", U] :
    T extends { a: infer U, b: infer U extends number } ? ["number", U] :
    never;

type X9_T1 = T9<{ a: "a", b: "b" }>; // ["string", "a" | "b"]
type X9_T2 = T9<{ a: 1, b: 2 }>; // ["number", 1 | 2]
type X9_T3 = T9<{ a: object, b: object }>; // never
type X9_T4 = T9<{ a: "a", b: 1 }>; // never
