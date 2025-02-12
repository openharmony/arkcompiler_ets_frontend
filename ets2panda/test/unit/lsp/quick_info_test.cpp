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

#include "lsp/include/quick_info.h"
#include "lsp_api_test.h"
#include "lsp/include/internal_api.h"
#include <gtest/gtest.h>

using ark::es2panda::lsp::Initializer;

TEST_F(LSPAPITests, getPropertySymbolFromContextualType1)
{
    Initializer initializer = Initializer();
    es2panda_Context *ctx =
        initializer.CreateContext("contextual-type-test.sts", ES2PANDA_STATE_CHECKED,
                                  "interface objI { key : string; }\nlet obj : objI = { key:\"valueaaaaaaaaa,\" }");
    ASSERT_EQ(ContextState(ctx), ES2PANDA_STATE_CHECKED);
    size_t const offset = 54;
    auto node = ark::es2panda::lsp::GetTokenForQuickInfo(ctx, offset);
    ASSERT_NE(node, nullptr);
    auto containingObjectNode = ark::es2panda::lsp::GetContainingObjectLiteralNode(node);
    ASSERT_NE(containingObjectNode, nullptr);
    auto contextualTypeNode = ark::es2panda::lsp::GetContextualTypeNode(containingObjectNode->Parent());
    ASSERT_NE(contextualTypeNode, nullptr);
    ASSERT_EQ(contextualTypeNode->Type(), ark::es2panda::ir::AstNodeType::TS_INTERFACE_DECLARATION);
    auto propertyNode = ark::es2panda::lsp::GetPropertyNodeFromContextualType(containingObjectNode, contextualTypeNode);
    ASSERT_NE(propertyNode, nullptr);
    auto propertyDef = propertyNode->AsMethodDefinition();
    ASSERT_EQ(propertyDef->Key()->AsIdentifier()->Name(), "key");

    initializer.DestroyContext(ctx);
}

TEST_F(LSPAPITests, getPropertySymbolFromContextualType2)
{
    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext("contextual-type-test.sts", ES2PANDA_STATE_CHECKED,
                                                      "const record : Record<string,number> = { \"hello\":1234 }");
    ASSERT_EQ(ContextState(ctx), ES2PANDA_STATE_CHECKED);
    size_t const offset = 44;
    auto node = ark::es2panda::lsp::GetTokenForQuickInfo(ctx, offset);
    ASSERT_NE(node, nullptr);
    auto containingObjectNode = ark::es2panda::lsp::GetContainingObjectLiteralNode(node);
    ASSERT_NE(containingObjectNode, nullptr);
    auto contextualTypeNode = ark::es2panda::lsp::GetContextualTypeNode(containingObjectNode->Parent());
    ASSERT_NE(contextualTypeNode, nullptr);
    ASSERT_EQ(contextualTypeNode->Type(), ark::es2panda::ir::AstNodeType::CLASS_DEFINITION);
    auto propertyNode = ark::es2panda::lsp::GetPropertyNodeFromContextualType(containingObjectNode, contextualTypeNode);
    ASSERT_EQ(propertyNode->Type(), ark::es2panda::ir::AstNodeType::PROPERTY);

    initializer.DestroyContext(ctx);
}