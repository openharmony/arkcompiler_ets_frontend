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
#include "lsp/include/api.h"
#include "lsp_api_test.h"
#include "public/es2panda_lib.h"
#include "public/public.h"
#include <gtest/gtest.h>

namespace {
using ark::es2panda::lsp::Initializer;

class LspGetNodeTests : public LSPAPITests {
protected:
    static void SetUpTestSuite()
    {
        initializer_ = new Initializer();
        GenerateContexts(*initializer_);
    }

    static void TearDownTestSuite()
    {
        initializer_->DestroyContext(contexts_);
        delete initializer_;
        initializer_ = nullptr;
    }
    static void GenerateContexts(Initializer &initializer)
    {
        contexts_ = initializer.CreateContext("GetNodeTest.ets", ES2PANDA_STATE_CHECKED, R"(class Foo {
    Foo = 1;
})");
    }
    // NOLINTBEGIN(fuchsia-statically-constructed-objects, cert-err58-cpp)
    static inline es2panda_Context *contexts_ = nullptr;
    static inline Initializer *initializer_ = nullptr;
    // NOLINTEND(fuchsia-statically-constructed-objects, cert-err58-cpp)
};

TEST_F(LspGetNodeTests, GetProgramAst1)
{
    auto ctx = reinterpret_cast<ark::es2panda::public_lib::Context *>(contexts_);
    auto expectedAst = ctx->parserProgram->Ast();
    LSPAPI const *lspApi = GetImpl();
    auto ast = lspApi->getProgramAst(contexts_);
    ASSERT_EQ(reinterpret_cast<ark::es2panda::ir::AstNode *>(ast), expectedAst);
}

TEST_F(LspGetNodeTests, GetClassDefinition1)
{
    auto ctx = reinterpret_cast<ark::es2panda::public_lib::Context *>(contexts_);
    auto ast = ctx->parserProgram->Ast();
    LSPAPI const *lspApi = GetImpl();
    const std::string nodeName = "Foo";
    auto res = lspApi->getClassDefinition(reinterpret_cast<es2panda_AstNode *>(ast), nodeName);
    ASSERT_TRUE(reinterpret_cast<ark::es2panda::ir::AstNode *>(res)->IsClassDefinition());
    ASSERT_EQ(reinterpret_cast<ark::es2panda::ir::AstNode *>(res)->AsClassDefinition()->Ident()->Name(),
              nodeName.data());
}

TEST_F(LspGetNodeTests, GetIdentifier1)
{
    auto ctx = reinterpret_cast<ark::es2panda::public_lib::Context *>(contexts_);
    auto ast = ctx->parserProgram->Ast();
    LSPAPI const *lspApi = GetImpl();
    const std::string nodeName = "Foo";
    auto res = lspApi->getIdentifier(reinterpret_cast<es2panda_AstNode *>(ast), nodeName);
    ASSERT_TRUE(reinterpret_cast<ark::es2panda::ir::AstNode *>(res)->IsIdentifier());
    ASSERT_EQ(reinterpret_cast<ark::es2panda::ir::AstNode *>(res)->AsIdentifier()->Name(), nodeName.data());
}

}  // namespace