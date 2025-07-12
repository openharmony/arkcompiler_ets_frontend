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

function getTypeInfo(param: readonly number[] | string): string {
    if (typeof param === "string") {
        return "string";
    } else {
        return "array";
    }
}

function getTypeInfoGeneric(param: readonly Array<number> | boolean): string {
    if (typeof param === "boolean") {
        return "boolean";
    } else {
        return "generic_array";
    }
}

function getMultiUnionType(param: readonly string[] | number | boolean): string {
    if (typeof param === "boolean") {
        return "boolean";
    } else if (typeof param === "number") {
        return "number";
    } else {
        return "readonly_string_array";
    }
}

function getDoubleReadonlyArrays(param: readonly number[] | readonly string[]): string {
    // Simple type check without complex operations
    return "readonly_array";
}

function getTupleUnion(param: readonly [number, string] | boolean): string {
    if (typeof param === "boolean") {
        return "boolean";
    } else {
        return "readonly_tuple";
    }
}

function getReadonlyWithNull(param: readonly string[] | null): string {
    if (param === null) {
        return "null";
    } else {
        return "readonly_string_array";
    }
}

function main(): void {
    // Test basic readonly union - the core fix
    let result1 = getTypeInfo("hello");
    assertEQ(result1, "string");
    
    let result2 = getTypeInfo([1, 2, 3] as readonly number[]);
    assertEQ(result2, "array");
    
    // Test readonly generic union
    let result3 = getTypeInfoGeneric(true);
    assertEQ(result3, "boolean");
    
    let result5 = getMultiUnionType(true);
    assertEQ(result5, "boolean");
    
    let result6 = getMultiUnionType(42);
    assertEQ(result6, "number");
    
    let result7 = getMultiUnionType(["a", "b"] as readonly string[]);
    assertEQ(result7, "readonly_string_array");
    
    // Test readonly number[] | readonly string[]
    let result8 = getDoubleReadonlyArrays([1, 2] as readonly number[]);
    assertEQ(result8, "readonly_array");
    
    let result9 = getDoubleReadonlyArrays(["x", "y"] as readonly string[]);
    assertEQ(result9, "readonly_array");
    
    // Test readonly tuple
    let result10 = getTupleUnion(true);
    assertEQ(result10, "boolean");
    
    let result11 = getTupleUnion([42, "test"] as readonly [number, string]);
    assertEQ(result11, "readonly_tuple");
    
    // Test readonly with null
    let result12 = getReadonlyWithNull(null);
    assertEQ(result12, "null");
    
    let result13 = getReadonlyWithNull(["test"] as readonly string[]);
    assertEQ(result13, "readonly_string_array");
} 