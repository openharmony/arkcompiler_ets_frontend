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
#include <cstdio>
#include "lsp_api_test.h"
#include "public/es2panda_lib.h"
#include "lsp/include/internal_api.h"
#include "ir/astNode.h"
#include "lsp/include/string_completions.h"

using ark::es2panda::lsp::Initializer;

class SLCTests : public LSPAPITests {};

// SLC -> StringLiteralCompletions
TEST_F(SLCTests, SLCInterfaceTest)
{
    Initializer initializer = Initializer();
    es2panda_Context *context = initializer.CreateContext("not-found-node.ets", ES2PANDA_STATE_CHECKED,
                                                          "interface X { name: string}; let variable: X = { name: '");

    const size_t declarationPosition = 8;
    const size_t cursorPosition = 55;
    auto declaration = ark::es2panda::lsp::GetTouchingToken(context, declarationPosition, false);
    auto cursor = ark::es2panda::lsp::GetTouchingToken(context, cursorPosition, false);

    auto completions = ark::es2panda::lsp::GetStringLiteralCompletions(cursor, declaration);
    ASSERT_TRUE(completions != std::nullopt);

    std::string name = "name";
    std::string type = "string";
    auto expectedInsertText = name += std::string(": ") += type;
    ASSERT_TRUE(completions->GetEntries().front().GetInsertText() == expectedInsertText);

    initializer.DestroyContext(context);
}

TEST_F(SLCTests, SLCClassDeclarationTest)
{
    Initializer initializer = Initializer();
    es2panda_Context *context = initializer.CreateContext("not-found-node.ets", ES2PANDA_STATE_CHECKED,
                                                          "class C { name: string}; let variable: C = { name: '");

    const size_t declarationPosition = 4;
    const size_t cursorPosition = 52;
    auto declaration = ark::es2panda::lsp::GetTouchingToken(context, declarationPosition, false);
    auto cursor = ark::es2panda::lsp::GetTouchingToken(context, cursorPosition, false);

    auto completions = ark::es2panda::lsp::GetStringLiteralCompletions(cursor, declaration);
    ASSERT_TRUE(completions != std::nullopt);

    std::string name = "name";
    std::string type = "string";
    auto expectedInsertText = name += std::string(": ") += type;
    ASSERT_TRUE(completions->GetEntries().front().GetInsertText() == expectedInsertText);

    initializer.DestroyContext(context);
}
