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


// infer to tuple element
type T1<T extends any[]> = T extends [infer U extends string] ? ["string", U] :
    T extends [infer U extends number] ? ["number", U] :
    never;

type X1_T1 = T1<["a"]>; // ["string", "a"]
type X1_T2 = T1<[1]>; // ["number", 1]
type X1_T3 = T1<[object]>; // never

// infer to argument
type T2<T extends (...args: any[]) => void> = T extends (a: infer U extends string) => void ? ["string", U] :
    T extends (a: infer U extends number) => void ? ["number", U] :
    never;

type X2_T1 = T2<(a: "a") => void>; // ["string", "a"]
type X2_T2 = T2<(a: 1) => void>; // ["number", 1]
type X2_T3 = T2<(a: object) => void>; // never

// infer to return type
type T3<T extends (...args: any[]) => any> =
    T extends (...args: any[]) => (infer U extends string) ? ["string", U] :
    T extends (...args: any[]) => (infer U extends number) ? ["number", U] :
    never;

type X3_T1 = T3<() => "a">; // ["string", "a"]
type X3_T2 = T3<() => 1>; // ["number", 1]
type X3_T3 = T3<() => object>; // never

// infer to instance type
type T4<T extends new (...args: any[]) => any> =
    T extends new (...args: any[]) => (infer U extends { a: string }) ? ["string", U] :
    T extends new (...args: any[]) => (infer U extends { a: number }) ? ["number", U] :
    never;

type X4_T1 = T4<new () => { a: "a" }>; // ["string", { a: "a" }]
type X4_T2 = T4<new () => { a: 1 }>; // ["number", { a: 1 }]
type X4_T3 = T4<new () => { a: object }>; // never
