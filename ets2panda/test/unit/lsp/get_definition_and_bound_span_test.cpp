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

#include <cstddef>
#include <iostream>
#include "lsp_api_test.h"
#include "lsp/include/get_definition_and_bound_span.h"
#include <gtest/gtest.h>

namespace {

class LSPGetDefinitionAndBoundSpanTests : public LSPAPITests {};

TEST_F(LSPGetDefinitionAndBoundSpanTests, GetDefinitionAndBoundSpan_FunctionReference)
{
    const auto fileName = "GetDefinitionAndBoundSpan1.ets";
    const auto fileContent = R"(
function sum(a: number, b: number): number {
    return a + b;
}

let total = sum(5, 10);
)";

    const size_t offset = 79;
    const size_t index0 = 0;
    const size_t index3 = 3;
    const size_t index13 = 13;

    std::vector<std::string> files = {fileName};
    std::vector<std::string> texts = {fileContent};
    auto filePaths = CreateTempFile(files, texts);

    ark::es2panda::lsp::Initializer initializer;
    es2panda_Context *ctx = initializer.CreateContext(filePaths.at(index0).c_str(), ES2PANDA_STATE_CHECKED);

    const auto result = ark::es2panda::lsp::GetDefinitionAndBoundSpan(ctx, offset);

    EXPECT_FALSE(result.definitionInfo.fileName.empty());
    EXPECT_EQ(result.definitionInfo.fileName, filePaths.at(index0));
    EXPECT_EQ(result.definitionInfo.length, index3);
    EXPECT_EQ(result.boundSpan.length, index3);
    EXPECT_EQ(result.definitionInfo.start + result.definitionInfo.length, index13);

    const size_t expectedDefOffset = 10;
    EXPECT_EQ(result.definitionInfo.start, expectedDefOffset);
    initializer.DestroyContext(ctx);
}

TEST_F(LSPGetDefinitionAndBoundSpanTests, GetDefinitionAndBoundSpan_FunctionReferenceTwoFile)
{
    std::vector<std::string> fileNames = {"GetDefinitionAndBoundSpan_export.ets", "GetDefinitionAndBoundSpan2.ets"};
    std::vector<std::string> texts = {
        R"(export function A(a:number, b:number): number {
  return a + b;
}
export function B(a:number, b:number): number {
  return a + b;
})",
        R"(import {A} from "./GetDefinitionAndBoundSpan_export";
import {B} from "./GetDefinitionAndBoundSpan_export.ets";
A(1, 2);
B(1, 2);)"};

    auto filePaths = CreateTempFile(fileNames, texts);
    int const expectedFileCount = 2;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    const size_t offset = 116;
    const size_t index0 = 0;
    const size_t index1 = 1;
    const size_t index13 = 17;
    ark::es2panda::lsp::Initializer initializer;
    es2panda_Context *ctx = initializer.CreateContext(filePaths.at(index1).c_str(), ES2PANDA_STATE_CHECKED);

    const auto result = ark::es2panda::lsp::GetDefinitionAndBoundSpan(ctx, offset);

    EXPECT_FALSE(result.definitionInfo.fileName.empty());
    EXPECT_EQ(result.definitionInfo.fileName, filePaths.at(index0));
    EXPECT_EQ(result.definitionInfo.length, index1);
    EXPECT_EQ(result.boundSpan.length, index1);
    EXPECT_EQ(result.definitionInfo.start + result.definitionInfo.length, index13);

    const size_t expectedDefOffset = 16;
    EXPECT_EQ(result.definitionInfo.start, expectedDefOffset);
    initializer.DestroyContext(ctx);
}

}  // namespace