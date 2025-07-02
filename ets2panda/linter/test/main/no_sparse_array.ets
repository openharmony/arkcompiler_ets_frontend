/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

let a = [1, , , 3];
let b = [];
let c: number[] = [];

let d = Promise.race<number>([]);
let e = Promise.all<number>([]);
let f = Promise.allSettled<number>([]);
let g = Promise.any<number>([]);
let h = Promise.resolve<number[]>([]);

let d1 = Promise.race([]);
let e1 = Promise.all([]);
let f1 = Promise.allSettled([]);
let g1 = Promise.any([]);
let h1 = Promise.resolve([]);

let i = Promise.race<number>([1.0]);
let j = Promise.all<number>([2.0]);
let k = Promise.allSettled<number>([3.0]);
let l = Promise.any<number>([4.0]);
let m = Promise.resolve<number[]>([5.0]);

let i1 = Promise.race([1]);
let j1 = Promise.all([2]);
let k1 = Promise.allSettled([3]);
let l1 = Promise.any([4]);
let m1 = Promise.resolve([5]);