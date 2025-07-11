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

// Comprehensive test case for TypeNode::Clone() implementations
// This test covers all TypeNode subclasses that were missing Clone implementations
// and caused assertion failures in ValidateGenericTypeAliasForClonedNode

// Test 1: TSTypeLiteral Clone
type ObjectType = { n: number, s: string, b: boolean };

// Test 2: TSNumberKeyword, TSStringKeyword, TSBooleanKeyword Clone
type NumType = number;
type StrType = string;
type BoolType = boolean;

// Test 3: TSVoidKeyword Clone (in function types)
type VoidFunc = () => void;

// Test 4: TSTypeOperator Clone (keyof operations)
type KeyofType<T extends keyof ObjectType> = T;

// Test 5: TSIndexedAccessType Clone
type IndexedType<K extends keyof ObjectType> = ObjectType[K];

// Test 6: TSTupleType Clone
type TupleType = [a: number, b: string];

// Test 7: TSMappedType Clone
type MappedType = { [K in keyof ObjectType]: string };

// Test 8: TSFunctionType Clone
type FuncType<K extends keyof ObjectType> = (v: ObjectType[K]) => void;

// Test 9: TSLiteralType Clone (string literals)
type LiteralType<K extends 'n' | 's' | 'b'> = K;

// Test 10: TSUnionType Clone
type UnionType = string | number | boolean;

// Test 11: BrokenTypeNode Clone (created for invalid syntax)
// This will create BrokenTypeNode instances that need proper cloning
type InvalidType<K extends keyof InvalidMap> = K;

// Test 12: Complex nested type with multiple Clone implementations
type ComplexType<K extends keyof ObjectType = keyof ObjectType> = {
    kind: K,
    value: ObjectType[K],
    handler: (v: ObjectType[K]) => void,
    tuple: [K, ObjectType[K]],
    mapped: { [P in K]: ObjectType[P] }
};

// Test instantiation to trigger ValidateGenericTypeAliasForClonedNode
declare const test1: ComplexType<'n'>;
declare const test2: ComplexType<'s'>;
declare const test3: ComplexType<'b'>;

/* Expected errors (these are normal for ETS, but should not crash): */
/* @@? 1:3 Error TypeError: Class 'UnionType' is already defined with different type. */
/* @@? 1:3 Error TypeError: Class 'TupleType' is already defined with different type. */
/* @@? 21:19 Error SyntaxError: Invalid Type. */
/* @@? 21:24 Error SyntaxError: Label must be followed by a loop statement. */
/* @@? 21:24 Error TypeError: Type name 'number' used in the wrong context */
/* @@? 21:30 Error SyntaxError: Unexpected token ','. */
/* @@? 21:32 Error SyntaxError: Unexpected token 's'. */
/* @@? 21:35 Error SyntaxError: Label must be followed by a loop statement. */
/* @@? 21:35 Error TypeError: Type name 'string' used in the wrong context */
/* @@? 21:41 Error SyntaxError: Unexpected token ','. */
/* @@? 21:43 Error SyntaxError: Unexpected token 'b'. */
/* @@? 21:46 Error SyntaxError: Unexpected token 'boolean'. */
/* @@? 21:46 Error SyntaxError: Label must be followed by a loop statement. */
/* @@? 32:42 Error TypeError: The `keyof` keyword can only be used for class or interface type. */
/* @@? 35:44 Error TypeError: The `keyof` keyword can only be used for class or interface type. */
/* @@? 35:59 Error SyntaxError: Unexpected token ']'. */
/* @@? 35:59 Error SyntaxError: Unexpected token, expected ']'. */
/* @@? 35:60 Error SyntaxError: Unexpected token ']'. */
/* @@? 38:19 Error TypeError: Cannot find type 'a'. */
/* @@? 38:20 Error SyntaxError: Unexpected token, expected ',' or ']'. */
/* @@? 38:20 Error SyntaxError: Unexpected token ':'. */
/* @@? 38:22 Error SyntaxError: Unexpected token 'number'. */
/* @@? 38:22 Error TypeError: Type name 'number' used in the wrong context */
/* @@? 38:28 Error SyntaxError: Unexpected token ','. */
/* @@? 38:30 Error SyntaxError: Unexpected token 'b'. */
/* @@? 38:33 Error SyntaxError: Label must be followed by a loop statement. */
/* @@? 38:33 Error TypeError: Type name 'string' used in the wrong context */
/* @@? 38:39 Error SyntaxError: Unexpected token ']'. */
/* @@? 41:19 Error SyntaxError: Invalid Type. */
/* @@? 41:22 Error TypeError: Unresolved reference K */
/* @@? 41:24 Error SyntaxError: Unexpected token, expected ',' or ']'. */
/* @@? 41:24 Error SyntaxError: Unexpected token 'in'. */
/* @@? 41:24 Error TypeError: Unresolved reference in */
/* @@? 41:27 Error SyntaxError: Unexpected token 'keyof'. */
/* @@? 41:27 Error TypeError: Unresolved reference keyof */
/* @@? 41:33 Error SyntaxError: Unexpected token 'ObjectType'. */
/* @@? 41:33 Error TypeError: Type name 'ObjectType' used in the wrong context */
/* @@? 41:43 Error SyntaxError: Unexpected token ']'. */
/* @@? 41:44 Error SyntaxError: Unexpected token ':'. */
/* @@? 41:46 Error SyntaxError: Unexpected token 'string'. */
/* @@? 41:46 Error TypeError: Type name 'string' used in the wrong context */
/* @@? 44:41 Error TypeError: The `keyof` keyword can only be used for class or interface type. */
/* @@? 44:60 Error SyntaxError: Unexpected token, expected ']'. */
/* @@? 54:34 Error TypeError: Cannot find type 'InvalidMap'. */
/* @@? 54:44 Error TypeError: The `keyof` keyword can only be used for class or interface type. */
/* @@? 57:67 Error SyntaxError: Invalid Type. */
/* @@? 58:11 Error SyntaxError: Label must be followed by a loop statement. */
/* @@? 58:12 Error SyntaxError: Unexpected token ','. */
/* @@? 59:12 Error SyntaxError: Label must be followed by a loop statement. */
/* @@? 59:12 Error TypeError: Indexed access is not supported for such expression type. */
/* @@? 59:12 Error TypeError: Type name 'ObjectType' used in the wrong context */
/* @@? 59:25 Error SyntaxError: Unexpected token ','. */
/* @@? 60:14 Error SyntaxError: Label must be followed by a loop statement. */
/* @@? 60:29 Error SyntaxError: Unexpected token, expected ']'. */
/* @@? 60:36 Error SyntaxError: Unexpected token 'void'. */
/* @@? 60:40 Error SyntaxError: Unexpected token ','. */
/* @@? 61:12 Error SyntaxError: Label must be followed by a loop statement. */
/* @@? 61:16 Error TypeError: Type name 'ObjectType' used in the wrong context */
/* @@? 61:16 Error TypeError: Indexed access is not supported for such expression type. */
/* @@? 61:30 Error SyntaxError: Unexpected token ','. */
/* @@? 62:13 Error SyntaxError: Label must be followed by a loop statement. */
/* @@? 62:16 Error TypeError: Unresolved reference P */
/* @@? 62:18 Error SyntaxError: Unexpected token, expected ',' or ']'. */
/* @@? 62:18 Error SyntaxError: Unexpected token 'in'. */
/* @@? 62:21 Error SyntaxError: Unexpected token 'K'. */
/* @@? 62:22 Error SyntaxError: Unexpected token ']'. */
/* @@? 62:23 Error SyntaxError: Unexpected token ':'. */
/* @@? 62:25 Error SyntaxError: Unexpected token 'ObjectType'. */
/* @@? 62:25 Error TypeError: Type name 'ObjectType' used in the wrong context */
/* @@? 62:25 Error TypeError: Indexed access is not supported for such expression type. */