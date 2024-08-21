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
#include "ir/astNode.h"
#include "parser/ETSparser.h"

#include <gtest/gtest.h>

using ark::es2panda::compiler::ast_verifier::ASTVerifier;
using ark::es2panda::compiler::ast_verifier::InvariantNameSet;
using ark::es2panda::ir::AstNode;

namespace {
TEST_F(ASTVerifierTest, CatchClause)
{
    ASTVerifier verifier {Allocator()};

    char const *text = R"(
        let a = 10;
        try {
            a / 0;
        } catch (e) {
            if (e instanceof Error) {
            }
        }
    )";

    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.sts");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<AstNode *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    InvariantNameSet checks;
    checks.insert("VariableHasEnclosingScopeForAll");
    const auto &messages = verifier.Verify(ast, checks);
    ASSERT_EQ(messages.size(), 0);

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, LambdasHaveCorrectScope)
{
    ASTVerifier verifier {Allocator()};

    char const *text = R"(
        type BenchmarkFunc = () => void;

        function main() {
            const arr: number[] = [1, 2, 3, 4];
            const ITERATE_FUNC: BenchmarkFunc = () => {
                const length = arr.length;
            };
        }
    )";

    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.sts");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<AstNode *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    InvariantNameSet checks;
    checks.insert("VariableHasEnclosingScopeForAll");
    const auto &messages = verifier.Verify(ast, checks);
    ASSERT_EQ(messages.size(), 0);

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, ParametersInArrowFunctionExpression)
{
    ASTVerifier verifier {Allocator()};

    char const *text = R"(
        let b = 1;
        let f = (p: double) => b + p;
        function main () {
            assert f(42) == 43
        }
    )";

    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.sts");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<AstNode *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    InvariantNameSet checks;
    checks.insert("VariableHasEnclosingScopeForAll");
    const auto &messages = verifier.Verify(ast, checks);
    ASSERT_EQ(messages.size(), 0);

    impl_->DestroyContext(ctx);
}
}  // namespace
