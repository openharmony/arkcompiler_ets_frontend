/**
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

#include <gtest/gtest.h>
#include <cstddef>
#include <string>
#include "lsp_api_test.h"

TEST_F(LSPAPITests, GetDefinitionAtPosition1)
{
    std::vector<std::string> files = {"getDefinitionAtPosition1.sts", "getDefinitionAtPosition2.sts"};
    std::vector<std::string> texts = {R"(export function A(a:number, b:number): number {
    return a + b;
})",
                                      R"(import {A} from './getDefinitionAtPosition1';
A(1, 2);)"};
    auto filePaths = CreateTempFile(files, texts);
    size_t const expectedFileCount = 2;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 46;
    auto result = lspApi->getDefinitionAtPosition(filePaths[1].c_str(), offset);
    std::string expectedFileName = filePaths[0];
    size_t const expectedStart = 7;
    size_t const expectedLength = 60;
    ASSERT_EQ(result.fileName, expectedFileName);
    ASSERT_EQ(result.start, expectedStart);
    ASSERT_EQ(result.length, expectedLength);
}

TEST_F(LSPAPITests, GetDefinitionAtPosition2)
{
    std::vector<std::string> files = {"getDefinitionAtPosition3.sts"};
    std::vector<std::string> texts = {R"(
    function A(a:number, b:number) {
        return a + b;
    }
    A(1, 2);
    function A(a:number) {
        return a;
    }
    A(1);)"};
    auto filePaths = CreateTempFile(files, texts);
    int const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 70;
    auto result = lspApi->getDefinitionAtPosition(filePaths[0].c_str(), offset);
    std::string expectedFileName = filePaths[0];
    size_t const expectedStart = 5;
    size_t const expectedLength = 60;
    ASSERT_EQ(result.fileName, expectedFileName);
    ASSERT_EQ(result.start, expectedStart);
    ASSERT_EQ(result.length, expectedLength);

    size_t const offset1 = 134;
    auto result1 = lspApi->getDefinitionAtPosition(filePaths[0].c_str(), offset1);
    std::string expectedFileName1 = filePaths[0];
    size_t const expectedStart1 = 83;
    size_t const expectedLength1 = 46;
    ASSERT_EQ(result1.fileName, expectedFileName1);
    ASSERT_EQ(result1.start, expectedStart1);
    ASSERT_EQ(result1.length, expectedLength1);
}

TEST_F(LSPAPITests, GetDefinitionAtPosition3)
{
    std::vector<std::string> files = {"getDefinitionAtPosition4.sts", "getDefinitionAtPosition5.sts"};
    std::vector<std::string> texts = {R"(export function A(a:number, b:number): number {
    return a + b;
})",
                                      R"(import * as All from './getDefinitionAtPosition4';
All.A(1, 2);)"};
    auto filePaths = CreateTempFile(files, texts);
    size_t const expectedFileCount = 2;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 55;
    auto result = lspApi->getDefinitionAtPosition(filePaths[1].c_str(), offset);
    std::string expectedFileName = filePaths[0];
    size_t const expectedStart = 7;
    size_t const expectedLength = 60;
    ASSERT_EQ(result.fileName, expectedFileName);
    ASSERT_EQ(result.start, expectedStart);
    ASSERT_EQ(result.length, expectedLength);
}

TEST_F(LSPAPITests, GetDefinitionAtPosition4)
{
    std::vector<std::string> files = {"getDefinitionAtPosition6.sts", "getDefinitionAtPosition7.sts"};
    std::vector<std::string> texts = {R"(export class A {
Foo(a:number, b:number): number {
    return a + b;
}})",
                                      R"(import * as All from './getDefinitionAtPosition6';
let a = new All.A();
a.Foo(1, 2);)"};
    auto filePaths = CreateTempFile(files, texts);
    size_t const expectedFileCount = 2;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 74;
    auto result = lspApi->getDefinitionAtPosition(filePaths[1].c_str(), offset);
    std::string expectedFileName = filePaths[0];
    size_t const expectedStart = 17;
    size_t const expectedLength = 53;
    ASSERT_EQ(result.fileName, expectedFileName);
    ASSERT_EQ(result.start, expectedStart);
    ASSERT_EQ(result.length, expectedLength);
}

TEST_F(LSPAPITests, GetDefinitionAtPosition5)
{
    std::vector<std::string> files = {"getDefinitionAtPosition8.sts", "getDefinitionAtPosition9.sts"};
    std::vector<std::string> texts = {R"(export enum A {
a,
b})",
                                      R"(import * as All from './getDefinitionAtPosition8';
All.A.a;)"};
    auto filePaths = CreateTempFile(files, texts);
    size_t const expectedFileCount = 2;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 57;
    auto result = lspApi->getDefinitionAtPosition(filePaths[1].c_str(), offset);
    std::string expectedFileName = filePaths[0];
    size_t const expectedStart = 16;
    size_t const expectedLength = 1;
    ASSERT_EQ(result.fileName, expectedFileName);
    ASSERT_EQ(result.start, expectedStart);
    ASSERT_EQ(result.length, expectedLength);
}

TEST_F(LSPAPITests, GetDefinitionAtPosition6)
{
    std::vector<std::string> files = {"getDefinitionAtPosition10.sts", "getDefinitionAtPosition11.sts"};
    std::vector<std::string> texts = {R"(export class A {
Foo(a:number, b:number): number {
    return a + b;
}};
)",
                                      R"(import {A} from './getDefinitionAtPosition10';
let a = new A();
a.Foo(1, 2);)"};
    auto filePaths = CreateTempFile(files, texts);
    size_t const expectedFileCount = 2;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 66;
    auto result = lspApi->getDefinitionAtPosition(filePaths[1].c_str(), offset);
    std::string expectedFileName = filePaths[0];
    size_t const expectedStart = 17;
    size_t const expectedLength = 53;
    ASSERT_EQ(result.fileName, expectedFileName);
    ASSERT_EQ(result.start, expectedStart);
    ASSERT_EQ(result.length, expectedLength);
}

TEST_F(LSPAPITests, GetDefinitionAtPosition7)
{
    std::vector<std::string> files = {"getDefinitionAtPosition12.sts", "getDefinitionAtPosition13.sts"};
    std::vector<std::string> texts = {R"(export let a = 1;)",
                                      R"(import {a} from './getDefinitionAtPosition12';
let b = a;)"};
    auto filePaths = CreateTempFile(files, texts);
    size_t const expectedFileCount = 2;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 55;
    auto result = lspApi->getDefinitionAtPosition(filePaths[1].c_str(), offset);
    std::string expectedFileName = filePaths[0];
    size_t const expectedStart = 11;
    size_t const expectedLength = 5;
    ASSERT_EQ(result.fileName, expectedFileName);
    ASSERT_EQ(result.start, expectedStart);
    ASSERT_EQ(result.length, expectedLength);
}

TEST_F(LSPAPITests, GetDefinitionAtPosition8)
{
    std::vector<std::string> files = {"getDefinitionAtPosition14.sts", "getDefinitionAtPosition15.sts"};
    std::vector<std::string> texts = {R"(export interface I {})",
                                      R"(import {I} from './getDefinitionAtPosition14';
import * as All from './getDefinitionAtPosition14';
class A implements All.I {};)"};
    auto filePaths = CreateTempFile(files, texts);
    size_t const expectedFileCount = 2;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 8;
    auto result = lspApi->getDefinitionAtPosition(filePaths[1].c_str(), offset);
    std::string expectedFileName = filePaths[0];
    size_t const expectedStart = 7;
    size_t const expectedLength = 14;
    ASSERT_EQ(result.fileName, expectedFileName);
    ASSERT_EQ(result.start, expectedStart);
    ASSERT_EQ(result.length, expectedLength);

    size_t const offset1 = 122;
    result = lspApi->getDefinitionAtPosition(filePaths[1].c_str(), offset1);
    ASSERT_EQ(result.fileName, expectedFileName);
    ASSERT_EQ(result.start, expectedStart);
    ASSERT_EQ(result.length, expectedLength);
}
