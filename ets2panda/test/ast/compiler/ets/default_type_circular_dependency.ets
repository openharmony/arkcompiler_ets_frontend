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

class Racer {
    stat<Int = Racer.f()>;
}

/* @@? 17:9 Error TypeError: Only abstract or native methods can't have body. */
/* @@? 17:22 Error TypeError: 'f' type does not exist. */
/* @@? 17:23 Error SyntaxError: Unexpected token, expected '>'. */
/* @@? 17:24 Error SyntaxError: Unexpected token, expected '('. */
/* @@? 17:25 Error SyntaxError: Unexpected token, expected an identifier. */
/* @@? 17:25 Error SyntaxError: Parameter declaration should have an explicit type annotation. */
/* @@? 17:25 Error SyntaxError: Unexpected token, expected ',' or ')'. */
/* @@? 17:25 Error SyntaxError: Unexpected token '>'. */
