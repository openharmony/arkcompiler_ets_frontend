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

type NumFunc = () => void
type UT = NumFunc | number

function pi(): number {
    return 3.14
}

function main() {
    let v: UT = pi
    assertTrue((v as NumFunc)() == 3.14); // Is used 'assertTrue' due to #22840
}

/* @@? 24:17 Error TypeError: Type '() => Double' cannot be assigned to type '() => void|Double'  */
/* @@? 25:16 Error TypeError: Cannot use type 'void' as value.   */
/* @@? 25:17 Error TypeError: Cannot cast type '() => Double' to '() => void'  */
