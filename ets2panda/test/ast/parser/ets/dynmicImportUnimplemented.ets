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
    try {
        await import("hello")
            .then((m: JSValue): null => null)
            .catch((a: object | null | undefined): never => {
                throw a as Error
            })
    } catch (e: Error) {
        assertEQ(e.message, "Dynamic import is not supported")
        return
    }
    assertTrue(!"nothing was thrown")
}

/* @@? 18:15 Error SyntaxError: Unexpected token 'import'. */
/* @@? 18:15 Error TypeError: 'await' expressions require Promise object as argument. */
