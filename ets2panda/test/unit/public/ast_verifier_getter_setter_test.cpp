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
#include "ir/astNode.h"

#include <gtest/gtest.h>

using ark::es2panda::checker::ETSChecker;
using ark::es2panda::compiler::ast_verifier::ASTVerifier;
using ark::es2panda::compiler::ast_verifier::InvariantNameSet;
using ark::es2panda::ir::AstNode;

namespace {
TEST_F(ASTVerifierTest, ValidateCorrectGetterSetter)
{
    ETSChecker checker {};
    ASTVerifier verifier {Allocator()};

    char const *text =
        R"(
        class A {
            private _value: number = 0;
            set value(v: number): void {
                this._value = v
            }

            get value(): number {
                return this._value
            }
        }
    )";

    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.ets");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_LOWERED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_LOWERED);

    auto *ast = reinterpret_cast<AstNode *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    InvariantNameSet checks;
    checks.insert("GetterSetterValidationForAll");
    const auto &messages = verifier.Verify(ast, checks);

    // Expecting no warnings
    ASSERT_EQ(messages.size(), 0);

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, ValidateAbstractGettersSetters)
{
    ETSChecker checker {};
    ASTVerifier verifier {Allocator()};

    char const *text =
        R"(
        abstract class AbstractClass {
            private _value: int;
            abstract set value(v: int);
            abstract get value(): int;
        }
    )";

    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.ets");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_LOWERED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_LOWERED);

    auto *ast = reinterpret_cast<AstNode *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    InvariantNameSet checks;
    checks.insert("GetterSetterValidationForAll");
    const auto &messages = verifier.Verify(ast, checks);

    // Expecting no warnings
    ASSERT_EQ(messages.size(), 0);

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, ValidateAmbientGettersSetters)
{
    ETSChecker checker {};
    ASTVerifier verifier {Allocator()};

    char const *text =
        R"(
        declare class A {
            get foo(): int
            set foo(x: int): void
        }
    )";

    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.ets");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_LOWERED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_LOWERED);

    auto *ast = reinterpret_cast<AstNode *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    InvariantNameSet checks;
    checks.insert("GetterSetterValidationForAll");
    const auto &messages = verifier.Verify(ast, checks);

    // Expecting no warnings
    ASSERT_EQ(messages.size(), 0);

    impl_->DestroyContext(ctx);
}
}  // anonymous namespace
