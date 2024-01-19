/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

// Here is how "@ts-nocheck" works (this line shouldn't be reported): 
// @ts-nocheck
let x: number = null; // No error, type checking is suppressed
let y: number = null; // No error, type checking is suppressed

// @ts-expect-error
let z: number = 42 * "foo" // No error, type checking is suppressed

// Also, this line shouldn't be reported
// no @ts-ignore
if (false) {
    console.log("hello"); // No error, type checking is suppressed
}
