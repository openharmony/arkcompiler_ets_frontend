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

function main() {
    let b: byte = 1
    let s: Short = b
    let i: Int = b
    let l: Long = b
    let f: Float = b
    let d: Double = b
    let c: Char = b
    assertEQ(s.unboxed(), 1.0)
    assertEQ(i.unboxed(), 1.0)
    assertEQ(l.unboxed(), 1.0)
    assertEQ(f.unboxed(), 1.0)
    assertEQ(d.unboxed(), 1.0)
    assertEQ(c.unboxed(), 1.0)
}

