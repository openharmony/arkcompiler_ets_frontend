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
#include "ir/expressions/literals/stringLiteral.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/literals/numberLiteral.h"
#include "ir/expressions/literals/booleanLiteral.h"
#include "macros.h"
#include "parser/ETSparser.h"
#include "varbinder/ETSBinder.h"

#include <gtest/gtest.h>

using ark::es2panda::CompilerOptions;
using ark::es2panda::ScriptExtension;
using ark::es2panda::checker::ETSChecker;
using ark::es2panda::compiler::ast_verifier::ASTVerifier;
using ark::es2panda::compiler::ast_verifier::InvariantNameSet;
using ark::es2panda::ir::BinaryExpression;
using ark::es2panda::ir::BooleanLiteral;
using ark::es2panda::ir::Expression;
using ark::es2panda::ir::Identifier;
using ark::es2panda::ir::NumberLiteral;
using ark::es2panda::ir::SequenceExpression;
using ark::es2panda::ir::StringLiteral;
using ark::es2panda::lexer::Number;
using ark::es2panda::lexer::TokenType;
using ark::es2panda::parser::ETSParser;
using ark::es2panda::parser::Program;
using ark::es2panda::util::StringView;
using ark::es2panda::varbinder::ETSBinder;
using ark::es2panda::varbinder::FunctionScope;
using ark::es2panda::varbinder::LetDecl;
using ark::es2panda::varbinder::LocalScope;
using ark::es2panda::varbinder::LocalVariable;
using ark::es2panda::varbinder::VariableFlags;

TEST_F(ASTVerifierTest, NullParent)
{
    ark::es2panda::compiler::ast_verifier::ASTVerifier verifier {Allocator()};
    StringLiteral emptyNode;

    const auto check = "NodeHasParent";
    auto checks = ark::es2panda::compiler::ast_verifier::InvariantNameSet {};
    checks.insert(check);
    const auto &messages = verifier.Verify(&emptyNode, checks);
    bool hasParent = messages.empty();
    ASSERT_FALSE(hasParent);
    ASSERT_EQ(messages.size(), 1);

    ASSERT_EQ(messages[0].Invariant(), check);
}

TEST_F(ASTVerifierTest, NullRange)
{
    ark::es2panda::compiler::ast_verifier::ASTVerifier verifier {Allocator()};
    StringLiteral emptyNode;

    const auto check = "NodeHasSourceRange";
    auto checks = ark::es2panda::compiler::ast_verifier::InvariantNameSet {};
    checks.insert(check);
    const auto &messages = verifier.Verify(&emptyNode, checks);
    bool hasSourceRange = messages.empty();
    ASSERT_FALSE(hasSourceRange);
    ASSERT_EQ(messages.size(), 1);

    ASSERT_EQ(messages[0].Invariant(), check);
}

TEST_F(ASTVerifierTest, NullType)
{
    ASTVerifier verifier {Allocator()};
    StringLiteral emptyNode;

    auto check = "NodeHasType";
    auto checks = InvariantNameSet {};
    checks.insert(check);
    const auto &messages = verifier.Verify(&emptyNode, checks);
    bool hasType = messages.empty();
    ASSERT_EQ(hasType, false);
    ASSERT_NE(messages.size(), 0);

    ASSERT_EQ(messages[0].Invariant(), check);
}

TEST_F(ASTVerifierTest, WithoutScope)
{
    ASTVerifier verifier {Allocator()};
    StringLiteral emptyNode;

    auto checks = InvariantNameSet {};
    checks.insert("VariableHasScope");
    const auto &messages = verifier.Verify(&emptyNode, checks);

    ASSERT_EQ(messages.size(), 0);
}

TEST_F(ASTVerifierTest, ScopeTest)
{
    ASTVerifier verifier {Allocator()};
    Identifier ident(StringView("var_decl"), Allocator());
    LetDecl decl("test", &ident);
    LocalVariable local(&decl, VariableFlags::LOCAL);
    ident.SetVariable(&local);

    LocalScope scope(Allocator(), nullptr);
    FunctionScope parentScope(Allocator(), nullptr);
    scope.SetParent(&parentScope);
    scope.AddDecl(Allocator(), &decl, ScriptExtension::ETS);
    scope.BindNode(&ident);

    local.SetScope(&scope);

    auto checks = InvariantNameSet {};
    checks.insert("VariableHasScope");
    const auto &messages = verifier.Verify(&ident, checks);

    ASSERT_EQ(messages.size(), 0);
}

TEST_F(ASTVerifierTest, ScopeNodeTest)
{
    ASTVerifier verifier {Allocator()};
    Identifier ident(StringView("var_decl"), Allocator());
    LetDecl decl("test", &ident);
    LocalVariable local(&decl, VariableFlags::LOCAL);
    ident.SetVariable(&local);

    LocalScope scope(Allocator(), nullptr);
    FunctionScope parentScope(Allocator(), nullptr);
    scope.SetParent(&parentScope);
    scope.AddDecl(Allocator(), &decl, ScriptExtension::ETS);
    scope.BindNode(&ident);
    parentScope.BindNode(&ident);

    local.SetScope(&scope);

    auto checks = InvariantNameSet {};
    checks.insert("VariableHasEnclosingScope");
    const auto &messages = verifier.Verify(&ident, checks);

    ASSERT_EQ(messages.size(), 0);
}

TEST_F(ASTVerifierTest, ArithmeticExpressionCorrect1)
{
    ETSChecker etschecker {};
    ASTVerifier verifier {Allocator()};
    auto program = Program::NewProgram<ETSBinder>(Allocator());
    auto parser = ETSParser(&program, CompilerOptions {});

    auto left = NumberLiteral(Number {1});
    auto right = NumberLiteral(Number {6});
    auto arithmeticExpression = BinaryExpression(&left, &right, TokenType::PUNCTUATOR_PLUS);

    left.SetTsType(etschecker.GlobalIntType());
    right.SetTsType(etschecker.GlobalIntType());

    auto checks = InvariantNameSet {};
    checks.insert("ArithmeticOperationValid");
    const auto &messages = verifier.Verify(arithmeticExpression.AsBinaryExpression(), checks);
    ASSERT_EQ(messages.size(), 0);
}

TEST_F(ASTVerifierTest, ArithmeticExpressionCorrect2)
{
    ETSChecker etschecker {};
    ASTVerifier verifier {Allocator()};
    auto program = Program::NewProgram<ETSBinder>(Allocator());
    auto parser = ETSParser(&program, CompilerOptions {});

    constexpr uint32_t LEFT1_PARAM = 1;
    constexpr uint32_t LEFT2_PARAM = 12;
    constexpr uint32_t RIGHT2_PARAM = 6;
    auto left1 = NumberLiteral(Number {LEFT1_PARAM});
    auto left2 = NumberLiteral(Number {LEFT2_PARAM});
    auto right2 = NumberLiteral(Number {RIGHT2_PARAM});
    auto right1 = BinaryExpression(&left2, &right2, TokenType::PUNCTUATOR_MULTIPLY);
    auto arithmeticExpression = BinaryExpression(&left1, &right1, TokenType::PUNCTUATOR_PLUS);

    left1.SetTsType(etschecker.GlobalIntType());
    right1.SetTsType(etschecker.GlobalIntType());
    left2.SetTsType(etschecker.GlobalIntType());
    right2.SetTsType(etschecker.GlobalIntType());

    auto checks = InvariantNameSet {};
    checks.insert("ArithmeticOperationValid");
    const auto &messages = verifier.Verify(arithmeticExpression.AsBinaryExpression(), checks);
    ASSERT_EQ(messages.size(), 0);
}

TEST_F(ASTVerifierTest, ArithmeticExpressionNegative1)
{
    ETSChecker etschecker {};
    ASTVerifier verifier {Allocator()};
    auto program = Program::NewProgram<ETSBinder>(Allocator());
    auto parser = ETSParser(&program, CompilerOptions {});

    const StringView leftParam("1");
    constexpr uint32_t RIGHT_PARAM = 1;
    auto left = StringLiteral(leftParam);
    auto right = NumberLiteral(Number {RIGHT_PARAM});
    auto arithmeticExpression = BinaryExpression(&left, &right, TokenType::PUNCTUATOR_DIVIDE);

    left.SetTsType(etschecker.GlobalETSStringLiteralType());
    right.SetTsType(etschecker.GlobalIntType());

    auto checks = InvariantNameSet {};
    checks.insert("ArithmeticOperationValid");
    const auto &messages = verifier.Verify(arithmeticExpression.AsBinaryExpression(), checks);

    ASSERT_EQ(messages.size(), 1);
}

TEST_F(ASTVerifierTest, ArithmeticExpressionNegative2)
{
    ETSChecker etschecker {};
    ASTVerifier verifier {Allocator()};
    auto program = Program::NewProgram<ETSBinder>(Allocator());
    auto parser = ETSParser(&program, CompilerOptions {});
    auto left = BooleanLiteral(true);
    auto right = NumberLiteral(Number {1});
    auto arithmeticExpression = BinaryExpression(&left, &right, TokenType::PUNCTUATOR_DIVIDE);

    left.SetTsType(etschecker.GlobalETSStringLiteralType());
    right.SetTsType(etschecker.GlobalIntType());

    auto checks = InvariantNameSet {};
    checks.insert("ArithmeticOperationValid");
    const auto &messages = verifier.Verify(arithmeticExpression.AsBinaryExpression(), checks);

    ASSERT_EQ(messages.size(), 1);
}

TEST_F(ASTVerifierTest, SequenceExpressionType)
{
    ASTVerifier verifier {Allocator()};
    auto checker = ETSChecker();
    auto *last = Tree(Node<NumberLiteral>(Number {3}));
    auto *sequenceExpression = Tree(Node<SequenceExpression>(
        Nodes<Expression>(Node<NumberLiteral>(Number {1}), Node<NumberLiteral>(Number {2}), last)));

    last->SetTsType(checker.GlobalIntType());
    sequenceExpression->SetTsType(checker.GlobalIntType());

    auto checks = InvariantNameSet {};
    checks.insert("SequenceExpressionHasLastType");
    const auto &messages = verifier.Verify(sequenceExpression, checks);

    ASSERT_EQ(messages.size(), 0);
}

TEST_F(ASTVerifierTest, VariableNameIdentifierNameSameNegative)
{
    ark::es2panda::compiler::ast_verifier::ASTVerifier verifier {Allocator()};
    char const *text = R"(
        function main(): void {
            let tmp = 1;
            let lambda2: (value: int) => Int = (value: int): Int => {
                let a = 42;
                let num: Int = new Int(a + value);
                return num;
            }
            let n_tmp = tmp + 2;
            return 1;
        }
    )";

    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.sts");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<ark::es2panda::ir::ETSScript *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    // Note(@kirillbychkov): Change Identifier name in variable lambda2
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
        ->AsVariableDeclaration()
        ->Declarators()[0]
        ->AsVariableDeclarator()
        ->Id()
        ->AsIdentifier()
        ->SetName("not_name");

    const auto check = "VariableNameIdentifierNameSameForAll";
    auto checks = ark::es2panda::compiler::ast_verifier::InvariantNameSet {};
    checks.insert(check);
    const auto &messages = verifier.Verify(ast, checks);
    ASSERT_EQ(messages.size(), 1);

    ASSERT_EQ(messages[0].Invariant(), check);

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, VariableNameIdentifierNameSame)
{
    ark::es2panda::compiler::ast_verifier::ASTVerifier verifier {Allocator()};
    char const *text = R"(
        function main(): void {
            let tmp = 1;
            let lambda2: (value: int) => Int = (value: int): Int => {
                let a = 42;
                let num: Int = new Int(a + value);
                return num;
            }
            let n_tmp = tmp + 2;
            return 1;
        }
    )";

    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.sts");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<ark::es2panda::ir::ETSScript *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    auto checks = ark::es2panda::compiler::ast_verifier::InvariantNameSet {};
    checks.insert("VariableNameIdentifierNameSameForAll");
    const auto &messages = verifier.Verify(ast, checks);
    ASSERT_EQ(messages.size(), 0);
    impl_->DestroyContext(ctx);
}
