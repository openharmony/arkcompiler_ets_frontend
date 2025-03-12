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

function id<T>(v: Object): T {
    return v as T
}

function f1(a: "aa") {
    return a as "bb"
}

function f2(a: "aa"): "bb" {
    return a as "bb"
}

function main() {
    let caught_counter = 0

    try {
        let s = id<"a" | "b" | "c">("d")
    } catch (error: ClassCastError) {
        caught_counter++;
    }

    let s = id<"a" | "b" | "c">("a")

    try {
        let y = s as "b"
    } catch (error: ClassCastError) {
        caught_counter++;
    }

    try {
        assertEQ(s as "c", "c")
    } catch (error: ClassCastError) {
        caught_counter++;
    }

    try {
        f1("aa");
    } catch (error: ClassCastError) {
        caught_counter++;
    }

    try {
        f2("aa");
    } catch (error: ClassCastError) {
        caught_counter++;
    }

    assertEQ(caught_counter, 5)
}
