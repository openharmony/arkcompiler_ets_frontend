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

@interface MyAnno {
    testProperty1: string = 
    testProperty2: number
}

/* @@? 18:18 Error SyntaxError: Identifier expected, got ':'.  */
/* @@? 18:20 Error SyntaxError: number is a predefined type, cannot be used as an identifier  */
/* @@? 19:1 Error SyntaxError: Identifier expected, got '}'.  */
/* @@? 18:5 Error TypeError: Unresolved reference testProperty2 */
/* @@? 18:5 Error TypeError: Invalid value for annotation field, expected a constant literal. */
