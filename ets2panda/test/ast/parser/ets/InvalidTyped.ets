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

interface C extends ] {}

interface C extends A B {}

interface C extends {}

class A implements {}

class A implements I; {}

interface I implements A {}

interface I {
    override f(): void {}
// This should be the last test to show the absent of the '}'.


/* @@? 16:21 Error SyntaxError: Unexpected token, expected ','. */
/* @@? 16:21 Error SyntaxError: Identifier expected. */
/* @@? 16:21 Error TypeError: Interface expected here. */
/* @@? 16:23 Error SyntaxError: Identifier expected. */
/* @@? 16:23 Error TypeError: Interface expected here. */
/* @@? 18:1 Error TypeError: Merging declarations is not supported, please keep all definitions of classes, interfaces and enums compact in the codebase! */
/* @@? 18:1 Error TypeError: Variable 'C' has already been declared. */
/* @@? 18:23 Error SyntaxError: Unexpected token, expected ','. */
/* @@? 18:25 Error SyntaxError: Identifier expected. */
/* @@? 20:1 Error TypeError: Variable 'C' has already been declared. */
/* @@? 20:1 Error TypeError: Merging declarations is not supported, please keep all definitions of classes, interfaces and enums compact in the codebase! */
/* @@? 20:21 Error SyntaxError: Identifier expected. */
/* @@? 22:20 Error SyntaxError: Implements clause can not be empty. */
/* @@? 24:7 Error TypeError: Variable 'A' has already been declared. */
/* @@? 24:7 Error TypeError: Merging declarations is not supported, please keep all definitions of classes, interfaces and enums compact in the codebase! */
/* @@? 24:21 Error SyntaxError: Expected '{', got ','. */
/* @@? 24:21 Error SyntaxError: Unexpected token, expected ','. */
/* @@? 24:23 Error SyntaxError: Unexpected token '{'. */
/* @@? 26:13 Error SyntaxError: Interface declaration cannot have 'implements' clause. */
/* @@? 28:1 Error TypeError: Variable 'I' has already been declared. */
/* @@? 28:1 Error TypeError: Merging declarations is not supported, please keep all definitions of classes, interfaces and enums compact in the codebase! */
/* @@? 29:5 Error SyntaxError: 'override' modifier cannot appear in interfaces. */
/* @@? 56:1 Error SyntaxError: Unexpected token, expected '}'. */
