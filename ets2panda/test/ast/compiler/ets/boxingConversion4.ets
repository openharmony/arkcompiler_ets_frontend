/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

function refInt(a: Int): void {}

function main() : void {
    let a: Short = /* @@ label */new Short(3); // 3 is int, invocation context won't allow primitive narrowing
    let b: short = 2;
    let c: short = /* @@ label1 */-b; // due to unary operator promotion, '-b' will be int, which is not assignable
    let d: short = /* @@ label2 */b | b; // due to binary operator promotion, 'b | b' will be int, which is not assignable
    refInt(b); // primitive widening before boxing is not allowed
}

/* @@@ label Error TypeError: Expected 0 arguments, got 1. */
/* @@@ label Error TypeError: No matching construct signature for std.core.Short(int)  */
/* @@? 19:44 Error TypeError: Type 'int' is not compatible with type 'short' at index 1 */
/* @@@ label1 Error TypeError: Type 'int' cannot be assigned to type 'short'  */
/* @@@ label2 Error TypeError: Type 'int' cannot be assigned to type 'short'  */
