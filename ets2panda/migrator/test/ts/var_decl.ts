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
let global_a;
var global_b: number = 5, global_s = "string";
export const global_c = 'c';

let [s1, s2] = global_s.split("t");
let pi = 3.1416, [s3, s4] = s2.split("i");

function foo(): void {
    let a;
    let b = 4;
    let c: any;
    let d: boolean = false;
    let e, f: number, g = "car", h: boolean = true;

    const i = 5, j: string = "tomato";

    var k;
    var l = "hello"
    var m: number;
    var n: boolean = true;
    var o, p: string, q = 20, r: string = "something";

    let m = 10, [s1, s2] = r.split("t"), s = "string";
    let [s3, s4] = s.split("i");
}
