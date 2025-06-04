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

let a = +5        // 5 as number
let b = +"5"      // 5 as number
let c = -5        // -5 as number
let d = -"5"      // -5 as number
let e = ~5        // -6 as number
let f = ~"5"      // -6 as number
let g = +"string" // NaN as number

function returnTen(): string {
    return "-10"
}

function returnString(): string {
    return "string"
}

let x = +returnTen()    // -10 as number
let y = +returnString() // NaN

let t1: BigInt = BigInt(1)

let t2 = -t1;
let t3 = -9007199254740991n;

let t4 = -(new Number(1))
let t5 = -(BigInt(1))
