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

let a = foo() {
    switch (x) {
        "unreachable"
    }
}

/* @@? 16:9 Error TypeError: Unresolved reference foo  */
/* @@? 16:9 Error TypeError: This expression is not callable.  */
/* @@? 18:9 Error SyntaxError: Unexpected token 'string literal', expected 'case' or 'default'.  */
/* @@? 18:9 Error SyntaxError: Expected ':', got 'string literal'.  */
