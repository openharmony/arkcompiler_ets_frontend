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


// Speculative lookahead for `infer T extends U ?`
type T10<T> = T extends (infer U extends number ? 1 : 0) ? 1 : 0; // ok, parsed as conditional
type X10_Y1<T> = T10<T extends number ? 1 : 0>;
type X10_T1_T1 = X10_Y1<number>;

type T11<T> = T extends ((infer U) extends number ? 1 : 0) ? 1 : 0; // ok, parsed as conditional
type T12<T> = T extends (infer U extends number) ? 1 : 0; // ok, parsed as `infer..extends` (no trailing `?`)
type T13<T> = T extends infer U extends number ? 1 : 0; // ok, parsed as `infer..extends` (conditional types not allowed in 'extends type')
type T14<T> = T extends keyof infer U extends number ? 1 : 0; // ok, parsed as `infer..extends` (precedence wouldn't have parsed the `?` as part of a type operator)
type T15<T> = T extends { [P in infer U extends keyof T ? 1 : 0]: 1; } ? 1 : 0; // ok, parsed as conditional
type T16<T> = T extends { [P in infer U extends keyof T]: 1; } ? 1 : 0; // ok, parsed as `infer..extends` (no trailing `?`)
type T17<T> = T extends { [P in keyof T as infer U extends P ? 1 : 0]: 1; } ? 1 : 0; // ok, parsed as conditional
type T18<T> = T extends { [P in keyof T as infer U extends P]: 1; } ? 1 : 0; // ok, parsed as `infer..extends` (no trailing `?`)
