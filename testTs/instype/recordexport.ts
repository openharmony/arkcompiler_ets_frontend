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

export default function hello(str: string): string {
    return str;
}

export var a: number = 1;
export let b: number = 2;
export const c: number = 3;
export let d: string = "world";

export class Calculator{}

export function add(x: number, y: number): number {
    return x + y;
}

export function minus(x: number, y: number): number {
    return x - y;
}

export type A = number;
export interface B {
    name: string;
    ids: number[];
}

hello(d);
hello("test");
let ret: A = minus(add(a, b), c);
let cal = new Calculator();
