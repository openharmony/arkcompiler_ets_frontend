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

import {A, B} from "./import_1.ets"

let b = new B(10);

// First level import with both types of error
/* @@? import_1.ets:21:17 Error TypeError: Type 'int' cannot be assigned to type 'String' */
/* @@? import_1.ets:24:5 Error SyntaxError: Identifier expected, got 'number literal'. */

// Second level import import with both types of error
/* @@? import_2.ets:17:17 Error TypeError: Type 'int' cannot be assigned to type 'String' */
/* @@? import_2.ets:20:5 Error SyntaxError: Unexpected token 'not_ok'. */

// Error in main file based on class from the most distant file
/* @@? master_file.ets:18:9 Error TypeError: Expected 0 arguments, got 1. */
/* @@? master_file.ets:18:9 Error TypeError: No matching construct signature for import_2.B(int) */
/* @@? master_file.ets:18:9 Error TypeError: Expected 0 arguments, got 1. */
/* @@? master_file.ets:18:9 Error TypeError: No matching construct signature for import_2.B(int) */