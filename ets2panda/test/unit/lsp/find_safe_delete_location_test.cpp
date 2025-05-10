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

#include "lsp/include/find_safe_delete_location.h"
#include "lsp_api_test.h"
#include "lsp/include/references.h"
#include <gtest/gtest.h>

namespace {
using ark::es2panda::lsp::Initializer;
}  // namespace

class FindSafeDeleteLocationTests : public LSPAPITests {};

TEST_F(FindSafeDeleteLocationTests, FindSafeDeleteLocationBasic)
{
    std::vector<std::string> files = {"safe_delete_test_basic.ets"};
    std::vector<std::string> texts = {R"(function foo() {} foo(); foo();)"};

    auto filePaths = CreateTempFile(files, texts);

    Initializer initializer;
    es2panda_Context *ctx = initializer.CreateContext(filePaths[0].c_str(), ES2PANDA_STATE_CHECKED);

    constexpr size_t TOKEN_POSITION = 9;
    constexpr size_t RESULT_SIZE = 3;
    auto astNode = ark::es2panda::lsp::GetTouchingToken(ctx, TOKEN_POSITION, false);

    auto declInfo = ark::es2panda::lsp::GetDeclInfoImpl(astNode);

    LSPAPI const *lspApi = GetImpl();
    auto locations = lspApi->FindSafeDeleteLocation(ctx, &declInfo);

    ASSERT_EQ(locations.size(), RESULT_SIZE);

    initializer.DestroyContext(ctx);
}

TEST_F(FindSafeDeleteLocationTests, FindSafeDeleteLocationNoResult)
{
    std::vector<std::string> files = {"safe_delete_test_no_result.ets"};
    std::vector<std::string> texts = {R"(let x = 1;)"};

    auto filePaths = CreateTempFile(files, texts);

    Initializer initializer;
    es2panda_Context *ctx = initializer.CreateContext(filePaths[0].c_str(), ES2PANDA_STATE_CHECKED);

    constexpr size_t TOKEN_POSITION = 4;
    constexpr size_t RESULT_SIZE = 1;
    auto astNode = ark::es2panda::lsp::GetTouchingToken(ctx, TOKEN_POSITION, false);

    auto declInfo = ark::es2panda::lsp::GetDeclInfoImpl(astNode);

    LSPAPI const *lspApi = GetImpl();
    auto locations = lspApi->FindSafeDeleteLocation(ctx, &declInfo);

    ASSERT_EQ(locations.size(), RESULT_SIZE);

    initializer.DestroyContext(ctx);
}

TEST_F(FindSafeDeleteLocationTests, FindSafeDeleteLocationDeclInfoEmpty)
{
    std::vector<std::string> files = {"safe_delete_test_empty.ets"};
    std::vector<std::string> texts = {R"(let x: number = 1;)"};

    auto filePaths = CreateTempFile(files, texts);

    Initializer initializer;
    es2panda_Context *ctx = initializer.CreateContext(filePaths[0].c_str(), ES2PANDA_STATE_CHECKED);

    std::tuple<std::string, std::string> declInfo = {"", ""};

    LSPAPI const *lspApi = GetImpl();
    auto locations = lspApi->FindSafeDeleteLocation(ctx, &declInfo);

    ASSERT_TRUE(locations.empty());

    initializer.DestroyContext(ctx);
}
