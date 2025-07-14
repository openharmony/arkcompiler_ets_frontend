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

function main () {
export namespace taskpool {
    function taskfinished(task:Task) : boolean {}

/* @@? 17:1 Error SyntaxError: Unexpected token 'export'. */
/* @@? 17:8 Error SyntaxError: Namespace is allowed only at the top level or inside a namespace. */
/* @@? 18:32 Error TypeError: Cannot find type 'Task'. */
/* @@? 25:1 Error SyntaxError: Unexpected token. */
/* @@? 25:1 Error SyntaxError: Expected '}', got 'end of stream'. */
