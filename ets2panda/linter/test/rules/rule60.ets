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

let n1 = 42
let s1 = "foo"
console.log(typeof n1) // "number"
console.log(typeof s1) // "string"
let n2: typeof n1
let s2: typeof s1

let n3 = 42
let s3 = "foo"
console.log(typeof n3) // "number"
console.log(typeof s3) // "string"
let n4: number
let s4: string