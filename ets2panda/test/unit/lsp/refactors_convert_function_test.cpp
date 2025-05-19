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

namespace {
using ark::es2panda::lsp::Initializer;

class LspGetRefTests : public LSPAPITests {
public:
    static constexpr std::string_view TO_NAMED_FUNCTION_KIND = "refactor.rewrite.function.named";
    static constexpr std::string_view INVALID_KIND = "aaabbbccc";
    static constexpr std::string_view TO_NAMED_FUNCTION_NAME = "Convert to named function";
};

TEST_F(LspGetRefTests, ConvertFunctionRefactor1)
{
    std::vector<std::string> files = {"convertFunctionRefactor1.ets"};
    std::vector<std::string> texts = {R"(const add = (x: number, y: number): number => {
     return x + y;
 };)"};
    auto filePaths = CreateTempFile(files, texts);
    size_t const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    LSPAPI const *lspApi = GetImpl();
    size_t const position = 8;
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext(filePaths[0].c_str(), ES2PANDA_STATE_CHECKED);
    auto result = lspApi->getApplicableRefactors(ctx, std::string(TO_NAMED_FUNCTION_KIND).c_str(), position);
    initializer.DestroyContext(ctx);
    ASSERT_EQ(std::string(TO_NAMED_FUNCTION_NAME), result.action.name);
}

TEST_F(LspGetRefTests, ConvertFunctionRefactor2)
{
    std::vector<std::string> files = {"convertFunctionRefactor2.ets"};
    std::vector<std::string> texts = {R"(function sub(a: number, b: number): number{
     return a - b;
 };)"};
    auto filePaths = CreateTempFile(files, texts);
    size_t const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    LSPAPI const *lspApi = GetImpl();
    size_t const position = 11;
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext(filePaths[0].c_str(), ES2PANDA_STATE_CHECKED);
    auto result = lspApi->getApplicableRefactors(ctx, std::string(TO_NAMED_FUNCTION_KIND).c_str(), position);
    initializer.DestroyContext(ctx);
    ASSERT_EQ(std::string(""), result.name);
}

TEST_F(LspGetRefTests, ConvertFunctionRefactor3)
{
    std::vector<std::string> files = {"convertFunctionRefactor3.ets"};
    std::vector<std::string> texts = {R"(const add = (x: number, y: number): number => {
     return x + y;
 };)"};
    auto filePaths = CreateTempFile(files, texts);
    size_t const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    LSPAPI const *lspApi = GetImpl();
    size_t const position = 8;
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext(filePaths[0].c_str(), ES2PANDA_STATE_CHECKED);
    auto result = lspApi->getApplicableRefactors(ctx, std::string(INVALID_KIND).c_str(), position);
    initializer.DestroyContext(ctx);
    ASSERT_EQ(std::string(""), result.name);
}
}  // namespace