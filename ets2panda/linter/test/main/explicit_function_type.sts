/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
let f1: Function = () => {}; // ERROR
let g1: Function = function() {}; // ERROR
let h1: Function = new Function('return 42'); // ERROR
let g2 = function() {}; // OK
let h2 = new Function('return 42'); // ERROR
let j1 = () => {}; // OK
let f2 = (x: number) => x + 1; // OK


type F<R> = () => R;
type F1<P, R> = (p: P) => R;
type F2<P1, P2, R> = (p1: P1, p2: P2) => R;

let f3: F<void> = () => {}; // OK
let g3: F<number> = () => 42; // OK
let h3: F1<string, number> = (s: string) => s.length; // OK
let i: F2<number, string, boolean> = (n: number, s: string) => s.length > n; // OK
