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

function foo(x: string|number): [string, number] {
    return null;
}

function nonreturning(x: "string"): never {
    throw 1;
}

function bar(x: any): undefined {
    return undefined;
}

function nullreturning(): null {
    return null;
}

function goo(x: {a: string, b: number}): void {
}

type condType<T> = T extends number ? number : string;

type OptionsFlags<Type> = {
  [Property in keyof Type]: boolean;
};

type CtorType<T> = new(n: number) => T;

type StringKeys = keyof string;
