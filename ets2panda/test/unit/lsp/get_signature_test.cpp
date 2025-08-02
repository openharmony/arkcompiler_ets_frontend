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

#include "lsp/include/api.h"
#include "lsp/include/internal_api.h"
#include "lsp/include/get_signature.h"
#include <gtest/gtest.h>
#include <cstddef>
#include "test/unit/lsp/lsp_api_test.h"
namespace {

using ark::es2panda::lsp::Initializer;

class LspGetSignatureTests : public LSPAPITests {};

TEST_F(LspGetSignatureTests, LspTests)
{
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext("get_signature_test.ets", ES2PANDA_STATE_CHECKED,
                                         R"(function add(a:number, b:number): number {
  return a + b;
}
add())");
    const LSPAPI *lspApi = GetImpl();
    const size_t offset = 65;
    lspApi->getSignatureHelpItems(ctx, offset);
    auto result = ark::es2panda::lsp::GetSignature(ctx, offset);
    initializer.DestroyContext(ctx);
    const size_t expectedCount = 2;
    const size_t expectedIndex = 0;
    const size_t expectedSpanLength = 0;
    const size_t expectedSpanStart = 65;
    const size_t typeIndex = 3;
    const size_t returnTypeIndex = 4;
    ASSERT_EQ(result.GetArgumentCount(), expectedCount);
    ASSERT_EQ(result.GetArgumentIndex(), expectedIndex);
    ASSERT_EQ(result.GetApplicableSpan().length, expectedSpanLength);
    ASSERT_EQ(result.GetApplicableSpan().start, expectedSpanStart);
    ASSERT_EQ(result.GetItems().at(0).GetPrefixDisplayParts().at(0).GetText(), "add");
    ASSERT_EQ(result.GetItems().at(0).GetPrefixDisplayParts().at(0).GetKind(), "functionName");
    ASSERT_EQ(result.GetItems().at(0).GetSuffixDisplayParts().at(returnTypeIndex).GetText(), "Double");
    ASSERT_EQ(result.GetItems().at(0).GetSuffixDisplayParts().at(returnTypeIndex).GetKind(), "keyword");
    ASSERT_EQ(result.GetItems().at(0).GetParameters().at(0).GetDisplayParts().at(0).GetText(), "a");
    ASSERT_EQ(result.GetItems().at(0).GetParameters().at(0).GetDisplayParts().at(typeIndex).GetText(), "Double");
    ASSERT_EQ(result.GetItems().at(0).GetParameters().at(1).GetDisplayParts().at(0).GetText(), "b");
    ASSERT_EQ(result.GetItems().at(0).GetParameters().at(1).GetDisplayParts().at(typeIndex).GetText(), "Double");
}

TEST_F(LspGetSignatureTests, LspTests2)
{
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext("get_signature_test.ets", ES2PANDA_STATE_CHECKED,
                                         R"(function add(a:number, b:number): number {
  return a + b;
}
add(11,))");
    const LSPAPI *lspApi = GetImpl();
    const size_t offset = 68;
    lspApi->getSignatureHelpItems(ctx, offset);
    auto result = ark::es2panda::lsp::GetSignature(ctx, offset);
    initializer.DestroyContext(ctx);
    const size_t expectedCount = 2;
    const size_t expectedIndex = 1;
    const size_t expectedSpanLength = 3;
    const size_t expectedSpanStart = 65;
    ASSERT_EQ(result.GetArgumentCount(), expectedCount);
    ASSERT_EQ(result.GetArgumentIndex(), expectedIndex);
    ASSERT_EQ(result.GetApplicableSpan().length, expectedSpanLength);
    ASSERT_EQ(result.GetApplicableSpan().start, expectedSpanStart);
}

TEST_F(LspGetSignatureTests, LspTests3)
{
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext("get_signature_test.ets", ES2PANDA_STATE_CHECKED,
                                         R"(function add(a:number, b): number {
  return a + b;
}
add(11,))");
    const LSPAPI *lspApi = GetImpl();
    const size_t offset = 61;
    lspApi->getSignatureHelpItems(ctx, offset);
    auto result = ark::es2panda::lsp::GetSignature(ctx, offset);
    initializer.DestroyContext(ctx);
    const size_t expectedCount = 2;
    const size_t expectedIndex = 1;
    const size_t expectedSpanLength = 3;
    const size_t expectedSpanStart = 58;
    const size_t typeIndex = 3;
    ASSERT_EQ(result.GetArgumentCount(), expectedCount);
    ASSERT_EQ(result.GetArgumentIndex(), expectedIndex);
    ASSERT_EQ(result.GetApplicableSpan().length, expectedSpanLength);
    ASSERT_EQ(result.GetApplicableSpan().start, expectedSpanStart);
    ASSERT_EQ(result.GetItems().at(0).GetParameters().at(1).GetDisplayParts().at(typeIndex).GetText(), "*ERROR_TYPE*");
}

}  // namespace