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

dim a = 0;
const b = 1;

function main(): void {
  a := b;
}

/* @@? 16:1 Error TypeError: Unresolved reference dim */
/* @@? 16:5 Error SyntaxError: Unexpected token 'a'. */
/* @@? 16:5 Error TypeError: Unresolved reference a */
/* @@? 20:6 Error SyntaxError: Label must be followed by a loop statement. */
/* @@? 20:6 Error SyntaxError: Unexpected token '='. */
/* @@? 20:8 Error SyntaxError: Unexpected token 'b'. */
