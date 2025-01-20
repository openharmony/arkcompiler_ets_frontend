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

#include "ast_verifier_test.h"
#include "ir/astNode.h"

#include <gtest/gtest.h>

using ark::es2panda::compiler::ast_verifier::CheckStructDeclaration;
using ark::es2panda::ir::AstNode;

namespace {

TEST_F(ASTVerifierTest, StructDeclaration)
{
    char const *text = R"(
        struct A {
            x : number = 0
        }
    )";

    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.sts");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_PARSED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_PARSED);

    auto *ast = reinterpret_cast<AstNode *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    const auto &messages = verifier_.Verify<CheckStructDeclaration>(ast);

    ASSERT_EQ(messages.size(), 1);

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, StructWithAnnotation)
{
    char const *text = R"(
    @interface Anno {
        name : string = "Tom";
    }

    @Anno
    struct A {
        a : number = 1
    }
    )";

    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.sts");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_PARSED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_PARSED);

    auto *ast = reinterpret_cast<AstNode *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    const auto &messages = verifier_.Verify<CheckStructDeclaration>(ast);

    ASSERT_EQ(messages.size(), 1);

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, StructWithComponent)
{
    char const *text = R"(
    @Component
    struct A {
        a : number = 1
    }
    )";

    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.sts");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_PARSED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_PARSED);

    auto *ast = reinterpret_cast<AstNode *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    const auto &messages = verifier_.Verify<CheckStructDeclaration>(ast);

    ASSERT_EQ(messages.size(), 1);

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, StructExtendsStruct)
{
    char const *text = R"(
    struct A {
    }
    struct B extends A {
    }
    )";

    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.sts");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_PARSED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_PARSED);

    auto *ast = reinterpret_cast<AstNode *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    const auto &messages = verifier_.Verify<CheckStructDeclaration>(ast);

    ASSERT_GT(messages.size(), 1);

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, StructExtendsClass)
{
    char const *text = R"(
    class A {
    }
    struct B extends A {
    }
    )";

    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.sts");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_PARSED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_PARSED);

    auto *ast = reinterpret_cast<AstNode *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    const auto &messages = verifier_.Verify<CheckStructDeclaration>(ast);

    ASSERT_EQ(messages.size(), 1);

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, StructExtendsEnum)
{
    char const *text = R"(
    enum Color {
        Red,
        Green,
        Blue
    }
    struct B extends Color {
    }
    )";

    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.sts");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_PARSED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_PARSED);

    auto *ast = reinterpret_cast<AstNode *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    const auto &messages = verifier_.Verify<CheckStructDeclaration>(ast);

    ASSERT_EQ(messages.size(), 1);

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, StructImplementInterface)
{
    char const *text = R"(
    interface A {
    }
    struct B implements A {
    }
    )";

    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.sts");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_PARSED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_PARSED);

    auto *ast = reinterpret_cast<AstNode *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    const auto &messages = verifier_.Verify<CheckStructDeclaration>(ast);

    ASSERT_EQ(messages.size(), 1);

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, StructExtendsInterface)
{
    char const *text = R"(
    interface A {
    }
    struct B extends A {
    }
    )";

    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.sts");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_PARSED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_PARSED);

    auto *ast = reinterpret_cast<AstNode *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    const auto &messages = verifier_.Verify<CheckStructDeclaration>(ast);

    ASSERT_GT(messages.size(), 0);

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, StructExport)
{
    char const *text = R"(
    export struct A {
    }
    )";

    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.sts");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_PARSED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_PARSED);

    auto *ast = reinterpret_cast<AstNode *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    const auto &messages = verifier_.Verify<CheckStructDeclaration>(ast);

    ASSERT_GT(messages.size(), 0);

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, StructInStruct)
{
    char const *text = R"(
    Struct A {
        Struct B {
        }
    }
    )";

    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.sts");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_PARSED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_ERROR);

    impl_->DestroyContext(ctx);
}

}  // namespace
