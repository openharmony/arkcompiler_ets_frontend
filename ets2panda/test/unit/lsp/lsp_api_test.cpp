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

#include "ir/astNode.h"
#include "ir/expressions/callExpression.h"
#include "lsp/include/api.h"
#include "lsp/include/internal_api.h"
#include <gtest/gtest.h>

#include "public/es2panda_lib.h"
#include "test/utils/ast_verifier_test.h"

using LSPAPITests = test::utils::AstVerifierTest;

TEST_F(LSPAPITests, GetTouchingToken1)
{
    es2panda_Context *ctx =
        CreateContextAndProceedToState(impl_, cfg_, "function A(a:number, b:number) {\n  return a + b;\n}\nA(1, 2);",
                                       "not-found-node.sts", ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);
    size_t const offset = 50;
    auto result = ark::es2panda::lsp::GetTouchingToken(ctx, offset, false);
    ASSERT_EQ(result, nullptr);

    auto result1 = ark::es2panda::lsp::GetTouchingToken(ctx, offset, true);
    ASSERT_EQ(result1, nullptr);
    impl_->DestroyContext(ctx);
}

TEST_F(LSPAPITests, GetTouchingToken2)
{
    es2panda_Context *ctx =
        CreateContextAndProceedToState(impl_, cfg_, "function A(a:number, b:number) {\n  return a + b;\n}\nA(1, 2);",
                                       "nested-node.sts", ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);
    size_t const offset = 51;
    auto result = ark::es2panda::lsp::GetTouchingToken(ctx, offset, false);
    auto ast = GetAstFromContext<ark::es2panda::ir::AstNode>(impl_, ctx);
    auto expectedNode = ast->FindChild(
        [](ark::es2panda::ir::AstNode *node) { return node->IsIdentifier() && node->AsIdentifier()->Name() == "A"; });
    ASSERT_EQ(result->DumpJSON(), expectedNode->DumpJSON());
    ASSERT_EQ(result->Start().index, expectedNode->Start().index);
    ASSERT_EQ(result->End().index, expectedNode->End().index);
    impl_->DestroyContext(ctx);
}

TEST_F(LSPAPITests, GetTouchingToken3)
{
    es2panda_Context *ctx =
        CreateContextAndProceedToState(impl_, cfg_, "function A(a:number, b:number) {\n  return a + b;\n}\nA(1, 2);",
                                       "first-node.sts", ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);
    size_t const offset = 51;
    auto result = ark::es2panda::lsp::GetTouchingToken(ctx, offset, true);
    auto ast = GetAstFromContext<ark::es2panda::ir::AstNode>(impl_, ctx);
    auto expectedNode = ast->FindChild([](ark::es2panda::ir::AstNode *node) { return node->IsExpressionStatement(); });
    ASSERT_EQ(result->DumpJSON(), expectedNode->DumpJSON());
    ASSERT_EQ(result->Start().index, expectedNode->Start().index);
    ASSERT_EQ(result->End().index, expectedNode->End().index);
    impl_->DestroyContext(ctx);
}

TEST_F(LSPAPITests, GetDefinitionAtPosition)
{
    es2panda_Context *ctx =
        CreateContextAndProceedToState(impl_, cfg_, "function main() {}", "file1.sts", ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);
    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 5;
    DefinitionInfo *result = lspApi->getDefinitionAtPosition("file1.sts", offset);
    ASSERT_EQ(result, nullptr);
    impl_->DestroyContext(ctx);
}
