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

try {} /* @@ label */ss (fgf) /* @@ label1 */{}
try {} /* @@ label2 */sfsfsf (fgf) /* @@ label3 */{} /* @@ label4 */finally {}
try {} catch (fgf) {} aaaaaaa /* @@ label5 */{}

try /* @@ label6 */[] /* @@ label7 */finally {}

/* @@? 16:22 Error SyntaxError: Missing catch or finally clause. */
/* @@? 16:46 Error SyntaxError: Unexpected token '{'. */
/* @@? 17:23 Error SyntaxError: Missing catch or finally clause. */
/* @@? 17:51 Error SyntaxError: Unexpected token '{'. */
/* @@? 17:69 Error SyntaxError: Unexpected token 'finally'. */
/* @@? 17:69 Error SyntaxError: Unexpected token 'finally'. */
/* @@? 18:46 Error SyntaxError: Unexpected token '{'. */
/* @@? 20:20 Error SyntaxError: Expected '{', got '['. */
/* @@? 20:20 Error SyntaxError: Expected '{', got '['. */
/* @@? 20:38 Error SyntaxError: Unexpected token 'finally'. */
/* @@? 20:38 Error SyntaxError: Unexpected token 'finally'. */
/* @@? 20:38 Error SyntaxError: Unexpected token 'finally'. */
/* @@? 36:1 Error SyntaxError: Expected '}', got 'eos'. */
/* @@? 36:1 Error SyntaxError: Missing catch or finally clause. */
