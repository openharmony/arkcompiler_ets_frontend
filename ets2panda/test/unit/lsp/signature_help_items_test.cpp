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

#include "lsp/include/signature_help_items.h"
#include "lsp/include/create_type_help_items.h"
#include "lsp_api_test.h"
#include <gtest/gtest.h>
#include "lsp/include/internal_api.h"
#include "test/unit/lsp/lsp_api_test.h"
#include "checker/types/signature.h"
#include "checker/checker.h"
#include "lexer/token/sourceLocation.h"
#include "public/es2panda_lib.h"
#include "ir/astNode.h"
#include "ir/expressions/functionExpression.h"
#include "ir/statements/functionDeclaration.h"

namespace {

class LSPSignatureHelpItemsTests : public LSPAPITests {};

ark::es2panda::ir::AstNode *FindTokenOnLeftOfPosition(es2panda_Context *context, size_t position)
{
    auto const tokenAtPosition = ark::es2panda::lsp::GetTouchingToken(context, position, false);
    if (tokenAtPosition->Start().index < position && tokenAtPosition->End().index > position) {
        return tokenAtPosition;
    }
    const auto ctx = reinterpret_cast<ark::es2panda::public_lib::Context *>(context);
    return ark::es2panda::lsp::FindPrecedingToken(position, ctx->parserProgram->Ast(), ctx->allocator);
}

TEST_F(LSPSignatureHelpItemsTests, CreateSignatureHelpItemTest)
{
    const auto fileName = "createSignatureHelpItemTest.ets";
    const auto fileText = R"(
 function testFunction<T, U>(param1: T, param2: U): number {
 return 0;
 }
 testFunction<number, string>(130, "test");
 )";
    const size_t index0 = 0;
    const size_t index1 = 1;
    const size_t position = 83;
    std::vector<std::string> files = {fileName};
    std::vector<std::string> texts = {fileText};
    auto filePaths = CreateTempFile(files, texts);
    ark::es2panda::lsp::Initializer initializer = ark::es2panda::lsp::Initializer();
    es2panda_Context *ctx = initializer.CreateContext(files.at(index0).c_str(), ES2PANDA_STATE_CHECKED, fileText);
    auto context = reinterpret_cast<ark::es2panda::public_lib::Context *>(ctx);
    auto callToken = FindTokenOnLeftOfPosition(ctx, position);
    const auto callNode = callToken->Parent();
    ASSERT_NE(callNode, nullptr);

    ASSERT_TRUE(callNode->IsCallExpression());
    ark::es2panda::ir::CallExpression *callExpr = nullptr;
    if (callNode->IsCallExpression()) {
        callExpr = callNode->AsCallExpression();
    }
    ark::es2panda::checker::Signature *signature = callExpr->Signature();
    ark::es2panda::lsp::SignatureHelpItem item =
        ark::es2panda::lsp::CreateSignatureHelpItem(context->allocator, *signature);
    bool found1 = false;
    bool found2 = false;
    EXPECT_FALSE(item.GetPrefixDisplayParts().empty());
    for (const auto &displayPart : item.GetPrefixDisplayParts()) {
        if (displayPart.GetText() == "<") {
            found1 = true;
        } else if (displayPart.GetText() == ">") {
            found2 = true;
        }
    }
    EXPECT_EQ(found1, true);
    EXPECT_EQ(found2, true);
    EXPECT_FALSE(item.GetSeparatorDisplayParts().empty());
    EXPECT_EQ(item.GetSeparatorDisplayParts().front().GetText(), ",");
    EXPECT_EQ(item.GetParameters().size(), 2U);
    EXPECT_EQ(item.GetParameters()[index0].GetName(), "param1");
    EXPECT_EQ(item.GetParameters()[index1].GetName(), "param2");
    item.Clear();
    initializer.DestroyContext(ctx);
}

TEST_F(LSPSignatureHelpItemsTests, CreateSignatureHelpItemParamsTest)
{
    const auto fileName = "CreateSignatureHelpItemParamsTest.ets";
    const auto fileText = R"(
 function testFunction<T, U>(param1: T, param2: U): number {
 return 0;
 }
 testFunction<number, string>(130, "test");
 )";
    const size_t index0 = 0;
    const size_t position = 83;
    const size_t position1 = 13;
    std::vector<std::string> files = {fileName};
    std::vector<std::string> texts = {fileText};
    auto filePaths = CreateTempFile(files, texts);
    ark::es2panda::lsp::Initializer initializer = ark::es2panda::lsp::Initializer();
    es2panda_Context *ctx = initializer.CreateContext(files.at(index0).c_str(), ES2PANDA_STATE_CHECKED, fileText);
    auto context = reinterpret_cast<ark::es2panda::public_lib::Context *>(ctx);
    auto callToken = FindTokenOnLeftOfPosition(ctx, position);
    const auto callNode = callToken->Parent();
    ASSERT_NE(callNode, nullptr);
    ASSERT_TRUE(callNode->IsCallExpression());
    ark::es2panda::ir::CallExpression *callExpr = nullptr;
    if (callNode->IsCallExpression()) {
        callExpr = callNode->AsCallExpression();
    }
    auto funcNode = FindTokenOnLeftOfPosition(ctx, position1);
    funcNode = funcNode->Parent();
    ASSERT_NE(funcNode, nullptr);
    ASSERT_TRUE(funcNode->IsMethodDefinition());
    ark::es2panda::ir::MethodDefinition *funcDecl = nullptr;
    if (funcNode->IsMethodDefinition()) {
        funcDecl = funcNode->AsMethodDefinition();
    }
    ark::ArenaVector<ark::es2panda::checker::Signature *> signatures(context->allocator->Adapter());
    signatures.push_back(callExpr->Signature());
    signatures.push_back(funcDecl->Function()->Signature());
    ark::es2panda::lsp::ArgumentListInfo argumentListInfo;
    const size_t argumentCount = 2;
    const size_t argumentIndex = 1;
    argumentListInfo.SetArgumentCount(argumentCount);
    argumentListInfo.SetArgumentIndex(argumentIndex);
    auto signatureHelpItems = ark::es2panda::lsp::CreateSignatureHelpItems(context->allocator, signatures,
                                                                           *callExpr->Signature(), argumentListInfo);
    EXPECT_EQ(signatureHelpItems.GetSelectedItemIndex(), index0);
    signatureHelpItems.Clear();
    initializer.DestroyContext(ctx);
}

}  // namespace