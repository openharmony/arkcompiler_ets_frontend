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

using ark::es2panda::compiler::ast_verifier::ASTVerifier;
using ark::es2panda::compiler::ast_verifier::InvariantNameSet;
using ark::es2panda::ir::ETSScript;

TEST_F(ASTVerifierTest, ProtectedAccessTestNegative4)
{
    ASTVerifier verifier {Allocator()};

    char const *text = R"(
        class Base {
            public a: int = 1;
            public protectedMethod() {
                this.a = 2;
            }
        }
        function main(): void {
            let base: Base = new Base();
            base.protectedMethod();
        }
    )";
    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.sts");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<ETSScript *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    ast->AsETSScript()
        ->Statements()[0]
        ->AsClassDeclaration()
        ->Definition()
        ->AsClassDefinition()
        ->Body()[1]
        ->AsClassElement()
        ->Value()
        ->AsFunctionExpression()
        ->Function()
        ->AsScriptFunction()
        ->Body()
        ->AsBlockStatement()
        ->Statements()[1]
        ->AsExpressionStatement()
        ->GetExpression()
        ->AsCallExpression()
        ->Signature()
        ->AddSignatureFlag(ark::es2panda::checker::SignatureFlags::PROTECTED);

    InvariantNameSet checks;
    checks.insert("ModifierAccessValidForAll");
    const auto &messages = verifier.Verify(ast, checks);
    ASSERT_EQ(messages.size(), 1);

    ASSERT_NE(checks.find(messages[0].Invariant()), checks.end());

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, ProtectedAccessTestNegative5)
{
    ASTVerifier verifier {Allocator()};

    char const *text = R"(
        class Base {
            public a: int = 1;
            public protectedMethod() {
                this.a = 2;
            }
        }
        class Derived extends Base {}
        function main(): void {
            let derived: Derived = new Derived();
            derived.protectedMethod();
        }
    )";
    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.sts");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<ETSScript *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    ast->AsETSScript()
        ->Statements()[0]
        ->AsClassDeclaration()
        ->Definition()
        ->AsClassDefinition()
        ->Body()[1]
        ->AsClassElement()
        ->Value()
        ->AsFunctionExpression()
        ->Function()
        ->AsScriptFunction()
        ->Body()
        ->AsBlockStatement()
        ->Statements()[1]
        ->AsExpressionStatement()
        ->GetExpression()
        ->AsCallExpression()
        ->Signature()
        ->AddSignatureFlag(ark::es2panda::checker::SignatureFlags::PROTECTED);

    InvariantNameSet checks;
    checks.insert("ModifierAccessValidForAll");
    const auto &messages = verifier.Verify(ast, checks);
    ASSERT_EQ(messages.size(), 1);

    ASSERT_NE(checks.find(messages[0].Invariant()), checks.end());

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, ProtectedAccessTestNegative6)
{
    ASTVerifier verifier {Allocator()};

    char const *text = R"(
        class Base {
            public a: int = 1;
            public protectedMethod() {
                this.a = 2;
            }
        }
        class Derived extends Base {}
        function main(): void {
            let derived: Base = new Derived();
            derived.protectedMethod();
        }
    )";
    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.sts");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<ETSScript *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    ast->AsETSScript()
        ->Statements()[0]
        ->AsClassDeclaration()
        ->Definition()
        ->AsClassDefinition()
        ->Body()[1]
        ->AsClassElement()
        ->Value()
        ->AsFunctionExpression()
        ->Function()
        ->AsScriptFunction()
        ->Body()
        ->AsBlockStatement()
        ->Statements()[1]
        ->AsExpressionStatement()
        ->GetExpression()
        ->AsCallExpression()
        ->Signature()
        ->AddSignatureFlag(ark::es2panda::checker::SignatureFlags::PROTECTED);

    InvariantNameSet checks;
    checks.insert("ModifierAccessValidForAll");

    const auto &messages = verifier.Verify(ast, checks);
    ASSERT_EQ(messages.size(), 1);

    ASSERT_NE(checks.find(messages[0].Invariant()), checks.end());

    impl_->DestroyContext(ctx);
}
