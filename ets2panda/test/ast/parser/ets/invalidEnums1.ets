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

enum EBadInitValue {
    Member1,
    Member2 = 1.0,
    Member3,
    Member4
}

enum EStrNotInit {
    Str1 = "str1",
    Str2
}


/* @@? 18:15 Error TypeError: Enumeration members can be initialized only by compile-time expressions and initializers must be of the same type. */
/* @@? 19:12 Error TypeError: Enumeration members can be initialized only by compile-time expressions and initializers must be of the same type. */
/* @@? 20:12 Error TypeError: Enumeration members can be initialized only by compile-time expressions and initializers must be of the same type. */
/* @@? 25:9 Error SyntaxError: All items of string-type enumeration should be explicitly initialized. */
