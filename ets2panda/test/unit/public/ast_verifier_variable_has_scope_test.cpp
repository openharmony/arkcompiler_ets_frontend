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
#include "ir/astNode.h"

#include <gtest/gtest.h>

using ark::es2panda::compiler::ast_verifier::ASTVerifier;
using ark::es2panda::compiler::ast_verifier::InvariantNameSet;
using ark::es2panda::ir::AstNode;

namespace {
TEST_F(ASTVerifierTest, ParametersInAsyncFunction)
{
    ASTVerifier verifier {Allocator()};

    char const *text = R"(
        async function bar(flag: boolean): Promise<double> {
            if (flag) {
                return 5.0;
            } else {
                return 1.0;
            }
        }
    )";

    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.sts");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<AstNode *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    InvariantNameSet checks;
    checks.insert("VariableHasScopeForAll");
    const auto &messages = verifier.Verify(ast, checks);
    ASSERT_EQ(messages.size(), 0);

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, TestUnions)
{
    ASTVerifier verifier {Allocator()};

    char const *text = R"(
        function assert_ccexc(f: () => void) {
            try {
                f();
                assert false : "exception expected";
            } catch (e) {
                assert(e instanceof ClassCastError);
            }
        }

        class A { }

        function test_unions() {
            assert_ccexc(() => { let f = ((x: A | undefined) => x as A | null); f(undefined); });
        }

        function main() {
            test_unions();
        }
    )";

    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.sts");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<AstNode *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    InvariantNameSet checks;
    checks.insert("VariableHasScopeForAll");
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
    checks.insert("VariableHasScopeForAll");
    const auto &messages = verifier.Verify(ast, checks);
    ASSERT_EQ(messages.size(), 0);

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, AsyncLambda1)
{
    ASTVerifier verifier {Allocator()};

    char const *text = R"(
        let fs: ((p: int) => int)[]
        function foo(i: int): ((p: int) => int) {
            return fs[i]
        }

        function main() {
            fs = [
                (p: int): int => p + 1,
            ]

            let ps: Object = new Object()
            ps = launch foo(0)

            let cnt = 0
            cnt += (await ps as Promise<(p: int) => int>)(0)
        }
    )";

    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.ets");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<AstNode *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    InvariantNameSet checks;
    checks.insert("VariableHasScopeForAll");
    const auto &messages = verifier.Verify(ast, checks);
    ASSERT_EQ(messages.size(), 0);

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, AsyncLambda2)
{
    ASTVerifier verifier {Allocator()};

    char const *text = R"(
        let global: int;
        async function func(param: int): Promise<String | null> {
            let local: int;
            let async_lambda: () => Promise<Object | null> = async (): Promise<Object | null> => {
                param;
                local;
                global;
                let x = 0;
                return null;
            }

            return null;
        }
    )";

    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.sts");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_LOWERED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_LOWERED);

    auto *ast = reinterpret_cast<AstNode *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    InvariantNameSet checks;
    checks.insert("VariableHasScopeForAll");
    const auto &messages = verifier.Verify(ast, checks);
    ASSERT_EQ(messages.size(), 0);

    impl_->DestroyContext(ctx);
}

}  // namespace
