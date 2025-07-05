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
#include "lsp/include/applicable_refactors.h"

namespace {
using ark::es2panda::lsp::Initializer;

class LspConvImpTests : public LSPAPITests {
public:
    static constexpr std::string_view TO_NAMED_IMPORT_KIND = "refactor.rewrite.import.named";
    static constexpr std::string_view TO_NAMED_IMPORT_NAME = "Convert namespace import to named imports";
    static constexpr std::string_view TO_NAMESPACE_IMPORT_KIND = "refactor.rewrite.import.namespace";
    static constexpr std::string_view TO_NAMESPACE_IMPORT_NAME = "Convert named imports to namespace import";
};

TEST_F(LspConvImpTests, ConvertImportRefactor1)
{
    std::vector<std::string> files = {"convertImportRefactor1.ets"};
    std::vector<std::string> texts = {R"(import { add, subtract, multiply } from './math';

const result = add(1, subtract(5, multiply(2, 3)));)"};
    auto filePaths = CreateTempFile(files, texts);
    size_t const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    size_t const position = 28;
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext(filePaths[0].c_str(), ES2PANDA_STATE_CHECKED);
    ark::es2panda::lsp::RefactorContext refactorContext;
    refactorContext.context = ctx;
    refactorContext.kind = std::string(TO_NAMESPACE_IMPORT_KIND);
    refactorContext.span.pos = position;
    auto result = GetApplicableRefactorsImpl(&refactorContext);
    initializer.DestroyContext(ctx);
    ASSERT_EQ(1, result.size());
    ASSERT_EQ(std::string(TO_NAMESPACE_IMPORT_NAME), result[0].action.name);
}

TEST_F(LspConvImpTests, ConvertImportRefactor2)
{
    std::vector<std::string> files = {"convertImportRefactor2.ets"};
    std::vector<std::string> texts = {R"(import * as math from './math';

const result = math.add(1, math.subtract(5, math.multiply(2, 3)));)"};
    auto filePaths = CreateTempFile(files, texts);
    size_t const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    size_t const position = 15;
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext(filePaths[0].c_str(), ES2PANDA_STATE_CHECKED);
    ark::es2panda::lsp::RefactorContext refactorContext;
    refactorContext.context = ctx;
    refactorContext.kind = std::string(TO_NAMED_IMPORT_KIND);
    refactorContext.span.pos = position;
    auto result = GetApplicableRefactorsImpl(&refactorContext);
    initializer.DestroyContext(ctx);
    ASSERT_EQ(1, result.size());
    ASSERT_EQ(std::string(TO_NAMED_IMPORT_NAME), result[0].action.name);
}
}  // namespace