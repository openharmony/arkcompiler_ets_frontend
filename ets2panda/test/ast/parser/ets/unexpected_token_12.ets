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

import { foo, bar } /* @@ label */kjfjf /* @@ label1 */988 /* @@ label2 */from /* @@ label3 */"./import_tests/modules/module"

/* @@@ label Error SyntaxError: Unexpected token, expected 'from'. */
/* @@@ label1 Error SyntaxError: Unexpected token, expected string literal. */
/* @@@ label2 Error SyntaxError: Unexpected token 'from'. */
/* @@? 16:75 Error TypeError: Unresolved reference from */
/* @@@ label3 Error SyntaxError: Unexpected token './import_tests/modules/module'. */
