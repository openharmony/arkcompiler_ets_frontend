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

// the test case is from fuzzer.
let callback = () => {for /* @@ label1 */aa !== /* @@ label2 */arr[idx]/* @@ label3 */)

/* @@@ label1 Error SyntaxError: Expected '(', got 'identification literal'. */
/* @@@ label1 Error TypeError: Unresolved reference aa */
/* @@@ label2 Error TypeError: Unresolved reference arr */
/* @@@ label2 Error TypeError: Indexed access is not supported for such expression type. */
/* @@@ label3 Error SyntaxError: Invalid left-hand side in 'For[In/Of]Statement'. */
/* @@? 26:1 Error SyntaxError: Unexpected token 'end of stream'. */
/* @@? 26:1 Error SyntaxError: Expected '}', got 'end of stream'. */
