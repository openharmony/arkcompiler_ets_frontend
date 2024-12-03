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
TEST_F(ASTVerifierTest, TSQualifiedName)
{
    ASTVerifier verifier {Allocator()};

    char const *text = R"(
        import * as Time from "std/time";

        function main() {
        let value = new Time.Chrono();
        }
    )";

    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.sts");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<AstNode *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    InvariantNameSet checks;
    checks.insert("IdentifierHasVariableForAll");
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
    checks.insert("IdentifierHasVariableForAll");
    const auto &messages = verifier.Verify(ast, checks);
    ASSERT_EQ(messages.size(), 0);

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, Lambdas)
{
    ASTVerifier verifier {Allocator()};

    char const *text = R"(
        type asyncLambda = () => Promise<void>;

        async function asyncFunc(): Promise<boolean> {
            return true;
        }

        function callAsyncLambda(): void {
            let is_call_async_lambda: boolean = false;

            let async_lambda: asyncLambda = async (): Promise<void> => {
                await asyncFunc();
                is_call_async_lambda = true;
            };
        }

        type I2v = (i: int) => void;
        type T1 = (lambda: (arg: int) => int, arg: int) => int;
        type T2 = (c: int) => int;

        const F1: I2v = (counter: int) => {
            let funcWithLambda: T1 = (lambda: (arg: int) => int, arg: int) => {
                return lambda(arg);
            };

            let it: T2 = (c: int): int => {
                return c;
            };

            while (counter > 0) counter = funcWithLambda(it, counter);
        };

        function main() {
            F1(44);
            return 0;
        }
    )";

    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.sts");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<AstNode *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    InvariantNameSet checks;
    checks.insert("IdentifierHasVariableForAll");
    const auto &messages = verifier.Verify(ast, checks);
    ASSERT_EQ(messages.size(), 0);

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, PromiseUndefined)
{
    ASTVerifier verifier {Allocator()};

    char const *text = R"(
        async function testAsyncVoidNothing() {}
    )";

    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.sts");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_LOWERED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_LOWERED);

    auto *ast = reinterpret_cast<AstNode *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    InvariantNameSet checks;
    checks.insert("IdentifierHasVariableForAll");
    const auto &messages = verifier.Verify(ast, checks);
    ASSERT_EQ(messages.size(), 0);

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, AnonymousClassId)
{
    ASTVerifier verifier {Allocator()};

    char const *text = R"(
        interface H {
        }

        class B {
            func: H = new H() {
            }
        }

        function main() {}
    )";

    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.sts");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<AstNode *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    InvariantNameSet checks;
    checks.insert("IdentifierHasVariableForAll");
    const auto &messages = verifier.Verify(ast, checks);
    ASSERT_EQ(messages.size(), 0);

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, EnumInts)
{
    ASTVerifier verifier {Allocator()};

    char const *text = R"(
        enum Color {
            Red = 1,
            Blue = 2
        }

        function main() {
            let color: Color = Color.Red;
            let name = color.getName();
        }
    )";

    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.sts");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<AstNode *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    InvariantNameSet checks;
    checks.insert("IdentifierHasVariableForAll");
    const auto &messages = verifier.Verify(ast, checks);
    ASSERT_EQ(messages.size(), 0);

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, EnumStrings)
{
    ASTVerifier verifier {Allocator()};

    char const *text = R"(
        enum Shape {
            Circle = "CIRCLE",
            Square = "SQUARE",
            Triangle = "TRIANGLE"
        }

        function main() {
            let shape = Shape.Circle.valueOf();
        }
    )";

    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.sts");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<AstNode *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    InvariantNameSet checks;
    checks.insert("IdentifierHasVariableForAll");
    const auto &messages = verifier.Verify(ast, checks);
    ASSERT_EQ(messages.size(), 0);

    impl_->DestroyContext(ctx);
}

}  // namespace
