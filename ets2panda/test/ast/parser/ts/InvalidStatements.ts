/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

try {
    let x = 8
}

try {}
finally (x)

try {}
catch () {}

declare namespace abc {
    let i = 0
}

/* @@? 20:1 Error SyntaxError: Missing catch or finally clause */
/* @@? 21:9 Error SyntaxError: Expected a '{', got '('. */
/* @@? 24:8 Error SyntaxError: Unexpected token ')' in catch parameter */
/* @@? 27:13 Error SyntaxError: Initializers are not allowed in ambient contexts. */
/* @@? 29:1 Error SyntaxError: Expected a '}' got 'eos'. */
