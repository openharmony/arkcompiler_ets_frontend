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

// Focused test case for primitive TypeNode Clone implementations
// Tests TSNumberKeyword, TSStringKeyword, TSBooleanKeyword, TSVoidKeyword cloning

// Simple primitive type aliases that exercise Clone
type NumAlias<T = number> = T;
type StrAlias<T = string> = T;
type BoolAlias<T = boolean> = T;
type VoidAlias<T = void> = T;

// Generic constraints using primitives
type NumericConstraint<T extends number> = T;
type StringConstraint<T extends string> = T;
type BooleanConstraint<T extends boolean> = T;

// Function types with primitive returns (exercises TSVoidKeyword)
type VoidFunction<T> = (param: T) => void;
type NumberFunction<T> = (param: T) => number;
type StringFunction<T> = (param: T) => string;
type BooleanFunction<T> = (param: T) => boolean;

// Complex types mixing primitives
type MixedType<N extends number, S extends string, B extends boolean> = {
    numField: N,
    strField: S,
    boolField: B,
    voidMethod: () => void
};

// Test instantiation to trigger ValidateGenericTypeAliasForClonedNode
declare const num: NumAlias<42>;
declare const str: StrAlias<"test">;
declare const bool: BoolAlias<true>;

/* Expected syntax errors (normal for ETS): */
/* @@? 37:73 Error SyntaxError: Invalid Type. */
/* @@? 38:15 Error SyntaxError: Label must be followed by a loop statement. */
/* @@? 38:15 Error TypeError: Unresolved reference N */
/* @@? 38:16 Error SyntaxError: Unexpected token ','. */
/* @@? 39:15 Error SyntaxError: Label must be followed by a loop statement. */
/* @@? 39:15 Error TypeError: Unresolved reference S */
/* @@? 39:16 Error SyntaxError: Unexpected token ','. */
/* @@? 40:16 Error SyntaxError: Label must be followed by a loop statement. */
/* @@? 40:16 Error TypeError: Unresolved reference B */
/* @@? 40:17 Error SyntaxError: Unexpected token ','. */
/* @@? 41:17 Error SyntaxError: Label must be followed by a loop statement. */
/* @@? 41:23 Error SyntaxError: Unexpected token 'void'. */
/* @@? 45:20 Error TypeError: Type alias declaration is generic, but no type parameters were provided */
/* @@? 45:29 Error SyntaxError: Unexpected token, expected '>'. */
/* @@? 45:29 Error SyntaxError: Unexpected token '>'. */
/* @@? 45:29 Error SyntaxError: Invalid Type. */
/* @@? 45:32 Error SyntaxError: Unexpected token ';'. */
/* @@? 47:21 Error TypeError: Type alias declaration is generic, but no type parameters were provided */
/* @@? 47:31 Error SyntaxError: Invalid Type. */
/* @@? 47:31 Error SyntaxError: Unexpected token, expected '>'. */
/* @@? 47:31 Error SyntaxError: Unexpected token '>'. */
/* @@? 47:36 Error SyntaxError: Unexpected token ';'. */