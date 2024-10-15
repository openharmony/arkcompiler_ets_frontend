/**
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "checker/ETSchecker.h"
#include "ir/expressions/identifier.h"
#include "parser/ETSparser.h"
#include "ir/astNode.h"

#include <gtest/gtest.h>

using ark::es2panda::compiler::ast_verifier::ASTVerifier;
using ark::es2panda::compiler::ast_verifier::InvariantNameSet;
using ark::es2panda::ir::AstNode;

TEST_F(ASTVerifierTest, RefAnnotationNullNegative)
{
    ASTVerifier verifier {Allocator()};

    char const *text = R"(
        let refNull = 10;
        let trueRef = refNull;
    )";

    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.sts");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<AstNode *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    auto *type = new ark::es2panda::ir::ETSPrimitiveType(ark::es2panda::ir::PrimitiveType::CHAR);

    ast->IterateRecursively([type](AstNode *astT) {
        if (astT->IsIdentifier()) {
            if (astT->AsIdentifier()->Name() == "trueRef") {
                astT->AsIdentifier()->SetTsTypeAnnotation(type);
            }
        }
    });

    InvariantNameSet checks;
    checks.insert("ReferenceTypeAnnotationIsNullForAll");

    const auto &messages = verifier.Verify(ast, checks);
    ASSERT_EQ(messages.size(), 1);
    const auto check = "ReferenceTypeAnnotationIsNullForAll";
    ASSERT_EQ(messages[0].Invariant(), check);

    delete type;
    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, RefAnnotationNull1)
{
    ASTVerifier verifier {Allocator()};

    char const *text = R"(
        let refNull = 10;
        let trueRef = refNull;
    )";

    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.sts");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<AstNode *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    InvariantNameSet checks;
    checks.insert("ReferenceTypeAnnotationIsNullForAll");
    const auto &messages = verifier.Verify(ast, checks);

    ASSERT_EQ(messages.size(), 0);

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, RefAnnotationNull2)
{
    ASTVerifier verifier {Allocator()};

    char const *text = R"(
        let refNull = 10;
    )";

    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.sts");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<AstNode *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    InvariantNameSet checks;
    checks.insert("ReferenceTypeAnnotationIsNullForAll");
    const auto &messages = verifier.Verify(ast, checks);

    ASSERT_EQ(messages.size(), 0);

    impl_->DestroyContext(ctx);
}
