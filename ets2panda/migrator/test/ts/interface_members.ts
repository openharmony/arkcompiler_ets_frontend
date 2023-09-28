/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
   f: number;
   foo(arg: string): I;
   bar<T, U>(t: T): U;
   (n: number, s: string): I;
   <T>(t: T, s: string): number;
   new(i: I): string;
   new<U>(u: U): number;
}
interface II {
    [n: number]: I;
    [s: string]: I;
}
