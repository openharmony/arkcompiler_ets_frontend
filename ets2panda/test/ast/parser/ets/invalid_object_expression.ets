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


let obj: Record<string, number> = {
    [this.viewModel.ads] : 123
}

/* @@? 18:5 Error SyntaxError: Unexpected token. */
/* @@? 18:6 Error SyntaxError: Unexpected token. */
/* @@? 18:6 Error TypeError: Cannot reference 'this' in this context. */
/* @@? 18:11 Error TypeError: Property 'viewModel' does not exist on type 'Error' */
/* @@? 18:24 Error SyntaxError: Unexpected token. */
/* @@? 18:26 Error SyntaxError: Unexpected token ':'. */
/* @@? 18:28 Error SyntaxError: Unexpected token '123'. */
/* @@? 19:1 Error SyntaxError: Unexpected token '}'. */
