/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

export declare function foo(p: A): void;
export declare function optional_foo(p?: A): void;
export declare class A {
    f1: string;
    static f2: double;

    constructor(p1: double, p2: string);

    foo(p: double): string;
    static bar(): double;
    optional_foo(p?: double): string;
}
export declare interface I {
    f1(p: string): double;
    f2(p: double): string;
}