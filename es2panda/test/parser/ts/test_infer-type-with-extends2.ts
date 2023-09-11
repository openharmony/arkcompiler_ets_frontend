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


// infer to type argument
type T5<T> =
    T extends Promise<infer U extends string> ? ["string", U] :
    T extends Promise<infer U extends number> ? ["number", U] :
    never;

type X5_T1 = T5<Promise<"a" | "b">>; // ["string", "a" | "b"]
type X5_T2 = T5<Promise<1 | 2>>; // ["number", 1 | 2]
type X5_T3 = T5<Promise<1n | 2n>>; // never

// infer to property type
type T6<T> =
    T extends { a: infer U extends string } ? ["string", U] :
    T extends { a: infer U extends number } ? ["number", U] :
    never;

type X6_T1 = T6<{ a: "a" }>; // ["string", "a"]
type X6_T2 = T6<{ a: 1 }>; // ["number", 1]
type X6_T3 = T6<{ a: object }>; // never

// infer twice with same constraint
type T7<T> =
    T extends { a: infer U extends string, b: infer U extends string } ? ["string", U] :
    T extends { a: infer U extends number, b: infer U extends number } ? ["number", U] :
    never;
