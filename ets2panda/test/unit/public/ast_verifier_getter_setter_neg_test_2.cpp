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
using ark::es2panda::ir::ETSParameterExpression;
using ark::es2panda::ir::Identifier;
using ark::es2panda::ir::MethodDefinitionKind;

namespace {

TEST_F(ASTVerifierTest, ValidateGetterArguments)
{
    ETSChecker checker {};
    ASTVerifier verifier {Allocator()};

    char const *text =
        R"(
        class A {
            private _value: number = 0;
            get value(): number {
                return this._value
            }

            set value(v: number): void {
                this._value = v
            }
        }
    )";

    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.ets");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<AstNode *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    // Create argument
    auto *ident = checker.AllocNode<Identifier>("ident", Allocator());
    auto *param = checker.AllocNode<ETSParameterExpression>(ident, nullptr);

    // Add argument to getter
    ast->IterateRecursively([param](ark::es2panda::ir::AstNode *child) {
        if (child->IsMethodDefinition()) {
            auto *const method = child->AsMethodDefinition();
            if (method->Kind() == MethodDefinitionKind::GET && method->Value()->IsFunctionExpression()) {
                auto *const function = method->Value()->AsFunctionExpression()->Function();
                auto &params = function->Params();
                ASSERT_EQ(params.size(), 0);
                params.push_back(param);
            }
        }
    });

    InvariantNameSet checks;
    checks.insert("GetterSetterValidationForAll");
    const auto &messages = verifier.Verify(ast, checks);

    // Expecting warning
    ASSERT_EQ(messages.size(), 1);
    ASSERT_EQ(messages[0].Cause(), "GETTER METHOD HAS INCORRECT NUMBER OF ARGUMENTS");

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, ValidateSetterReturnType)
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
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<AstNode *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    // Change setter return type
    ast->IterateRecursively([&checker](ark::es2panda::ir::AstNode *child) {
        if (child->IsMethodDefinition()) {
            auto *const method = child->AsMethodDefinition();
            if (method->Kind() == MethodDefinitionKind::SET && method->Value()->IsFunctionExpression()) {
                auto *const function = method->Value()->AsFunctionExpression()->Function();
                ASSERT_NE(function->ReturnTypeAnnotation(), nullptr);
                function->ReturnTypeAnnotation()->SetTsType(checker.GlobalIntType());
            }
        }
    });

    InvariantNameSet checks;
    checks.insert("GetterSetterValidationForAll");
    const auto &messages = verifier.Verify(ast, checks);

    // Expecting warning
    ASSERT_EQ(messages.size(), 1);
    ASSERT_EQ(messages[0].Cause(), "SETTER METHOD HAS NON-VOID RETURN TYPE");

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, ValidateSetterArguments)
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
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<AstNode *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    // Change setter arguments
    ast->IterateRecursively([](ark::es2panda::ir::AstNode *child) {
        if (child->IsMethodDefinition()) {
            auto *const method = child->AsMethodDefinition();
            if (method->Kind() == MethodDefinitionKind::SET && method->Value()->IsFunctionExpression()) {
                auto *const function = method->Value()->AsFunctionExpression()->Function();
                auto &params = function->Params();
                ASSERT_EQ(params.size(), 1);
                params.clear();
            }
        }
    });

    InvariantNameSet checks;
    checks.insert("GetterSetterValidationForAll");
    const auto &messages = verifier.Verify(ast, checks);

    // Expecting warning
    ASSERT_EQ(messages.size(), 1);
    ASSERT_EQ(messages[0].Cause(), "SETTER METHOD HAS INCORRECT NUMBER OF ARGUMENTS");

    impl_->DestroyContext(ctx);
}
}  // anonymous namespace
